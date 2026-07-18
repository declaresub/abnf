"""Live generative discovery across RFC grammar modules (issue #138).

Complements ``test_corpus_modules.py``: instead of replaying a frozen corpus,
this generates *fresh* inputs from each grammar every run and checks them.
Because generation runs in-process, Hypothesis shrinking works — a failure
minimizes to a small input.

It needs the pure-Python backend (the walker introspects the pure-Python
combinators, which the rust backend does not expose), so it skips under rust::

    ABNF_NO_RUST=1 pytest tests/fuzz/test_grammar_modules.py -v

The invariant is ambiguity-robust.  The walker generates from the grammar's
*derivation* semantics while the parser uses *longest-match*, so for ambiguous
rules (e.g. RFC 5646 language-tag) a valid derivation may not parse as the whole
rule.  Such inputs are ``assume``d away; what remains asserts that (a) parsing
never raises anything other than a clean ``ParseError`` — a non-``ParseError``
exception is a crash and fails the test — and (b) accepted inputs round-trip
(``value == src``).
"""

import importlib

import pytest

pytest.importorskip("hypothesis")

from strategy import has_prose, strategy_from_rule

import abnf.parser as _parser
from abnf import ParseError

pytestmark = pytest.mark.skipif(
    _parser._BACKEND != "python",
    reason=(
        "generative grammar fuzz needs the pure-Python backend for combinator "
        "introspection; rerun with ABNF_NO_RUST=1"
    ),
)

from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis.errors import Unsatisfiable  # noqa: E402

# Modules covered by live discovery.  The committed corpus (test_corpus_modules)
# covers the same modules for the python/rust differential; this adds fresh
# cases + shrinking on top.
MODULE_NAMES = [
    "rfc2616",
    "rfc3339",
    "rfc3629",
    "rfc3986",
    "rfc3987",
    "rfc4647",
    "rfc5234",
    "rfc5322",
    "rfc5646",
    "rfc5987",
    "rfc6265",
    "rfc6266",
    "rfc6797",
    "rfc7230",
    "rfc7231",
    "rfc7232",
    "rfc7233",
    "rfc7234",
    "rfc7235",
    "rfc7239",
    "rfc7240",
    "rfc7405",
    "rfc7489",
    "rfc7838",
    "rfc8187",
    "rfc8288",
    "rfc9051",
    "rfc9110",
    "rfc9111",
    "rfc9116",
    "rfc9651",
]

# Skip generated inputs longer than this before the ~O(n^2) parse (mirrors
# gen_corpus.MAX_INPUT_LEN); keeps the live suite fast on recursive grammars.
MAX_INPUT_LEN = 256


def _module_rule_params() -> list:
    return [
        pytest.param(module_name, rule.name, id=f"{module_name}:{rule.name}")
        for module_name in MODULE_NAMES
        for rule in sorted(
            importlib.import_module(f"abnf.grammars.{module_name}").Rule.rules(),
            key=lambda r: r.name,
        )
    ]


@pytest.mark.parametrize(("module_name", "rule_name"), _module_rule_params())
def test_generated_input_round_trips(module_name: str, rule_name: str):
    module = importlib.import_module(f"abnf.grammars.{module_name}")
    rule = module.Rule(rule_name)
    if has_prose(rule):
        pytest.skip(f"{rule_name} contains a Prose element; cannot generate")

    strategy = strategy_from_rule(rule)

    @given(src=strategy)
    @settings(
        max_examples=50,
        database=None,
        # Parse cost varies a lot across grammars (complex RFC 9051 IMAP inputs
        # can take a few hundred ms), so the per-example deadline would flake.
        deadline=None,
        suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
    )
    def check(src: str):
        assume(len(src) <= MAX_INPUT_LEN)
        try:
            node = rule.parse_all(src)
        except ParseError:
            # Grammar-derivation vs longest-match mismatch on an ambiguous rule
            # (or deeply-nested input, which the parser converts to ParseError,
            # issue #144); not a member of the language as the parser defines
            # it.  assume(False) raises to discard the example; the return keeps
            # `node` definitely bound for the assertion below (pyright can't see
            # assume never returns).  Any *other* exception type is a real crash
            # and fails the test.
            assume(False)
            return
        assert node.value == src

    try:
        check()
    except Unsatisfiable:
        # Every generated input was filtered (unparseable derivation or
        # over-length) — the rule is effectively ungeneratable by this walker,
        # same as the cases gen_corpus.py skips.  Not a failure.
        pytest.skip(f"{rule_name}: no parseable input could be generated")
