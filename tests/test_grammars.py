import pkgutil
import subprocess
import sys
import types
from importlib import import_module

import pytest

import abnf.grammars


@pytest.mark.parametrize("rfc", map(import_module, [f'{abnf.grammars.__name__}.{x[1]}' for x in pkgutil.walk_packages(abnf.grammars.__path__) if x[1] == 'cors' or x[1].startswith('rfc')]))
def test_grammar(rfc: types.ModuleType):
    """Catches rules used but not defined in grammar."""
    for rule in rfc.Rule.rules():
        if not hasattr(rule, 'definition'):
            print(str(rule))  # noqa: T201
        assert hasattr(rule, 'definition')


# Issue #245: a Prose parser always raises, so any rule whose definition can
# reach one has an alternative that cannot match.  That rarely shows up as a
# rejection -- more often some looser alternative absorbs the input and the
# parse tree comes out mis-attributed, which is how rfc9051's
# `resp-text-code` went unnoticed: `[MYCODE some text] hello` parsed happily
# as plain `text`, with no response code in the tree at all.
#
# tests/fuzz/strategy.py has known how to spot this all along; gen_corpus.py
# calls its has_prose() to *skip* such rules rather than report them.  The
# walker is repeated here rather than imported because that module needs
# hypothesis, which the tox envs do not install.
#
# The walk reads pure-Python combinator attributes, which the rust backend
# does not expose, so it runs in a subprocess with that backend forced off.
_PROSE_SWEEP = """
import os
os.environ["ABNF_NO_RUST"] = "1"
import pkgutil
from importlib import import_module

import abnf.grammars
from abnf._parser_python import (
    Alternation, Concatenation, Option, Prose, Repetition, Rule,
)


def has_prose(rule):
    seen = set()

    def walk(parser):
        if isinstance(parser, Prose):
            return True
        if isinstance(parser, Rule):
            if parser.name in seen:
                return False
            seen.add(parser.name)
            return walk(parser.definition)
        if isinstance(parser, (Alternation, Concatenation)):
            return any(walk(p) for p in parser.parsers)
        if isinstance(parser, Option):
            return walk(parser.alternation)
        if isinstance(parser, Repetition):
            return walk(parser.element)
        return False

    return walk(rule)


found = []
for _, name, _ in pkgutil.walk_packages(abnf.grammars.__path__):
    if not (name == "cors" or name.startswith("rfc")):
        continue
    module = import_module(f"{abnf.grammars.__name__}.{name}")
    found += [
        f"{name}: {rule.name}" for rule in module.Rule.rules() if has_prose(rule)
    ]
print("\\n".join(found))
"""


def test_245_no_grammar_reaches_a_prose_parser():
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _PROSE_SWEEP],
        capture_output=True,
        text=True,
        check=True,
    )
    unresolved = [line for line in result.stdout.splitlines() if line]
    assert not unresolved, (
        "these rules reach a Prose parser, so an alternative of theirs can "
        f"never match: {unresolved}"
    )
