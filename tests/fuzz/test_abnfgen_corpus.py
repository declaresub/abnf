"""Replay the abnfgen acceptance corpus (issue #251).

Each ``corpus_abnfgen/<module>.json`` holds strings abnfgen generated from
that module's *effective grammar as text* -- its own ABNF with imports
substituted in, reconstructed by ``effective_grammar.py``.  The module must
parse every one of them, because they were derived from the grammar it claims
to implement.

This is the sibling of ``test_corpus_modules.py``, and the difference is where
the strings came from.  ``gen_corpus.py`` walks the built combinators, so
generator and parser are the same object: a rule built from the wrong grammar
generates strings the wrong grammar accepts, and the corpus stays green no
matter what the loader did.  abnfgen never sees the built parser, so a
disagreement between grammar-as-written and parser-as-built shows up as a
rejection here.

It found two: RFC 9051 writes ``tagged-ext-comp`` and ``option-val-comp``
left-recursively, which a recursive-descent parser cannot evaluate, and under
longest-match alternation that took down every alternative -- the rules
matched nothing at all, not even the bare ``astring`` the first alternative
admits.  The Hypothesis walker had skipped both as ungeneratable, so the other
corpus was silent about them.

Parametrized per ``(module, rule)`` rather than per string, to keep collection
light.  Regenerate after changing a grammar::

    python tests/fuzz/gen_abnfgen_corpus.py <module>
"""

import importlib
import json
import pathlib

import pytest

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus_abnfgen"


def _params() -> list:
    params = []
    for path in sorted(CORPUS_DIR.glob("*.json")):
        corpus: dict[str, list[str]] = json.loads(path.read_text(encoding="utf-8"))
        for rule_name, cases in corpus.items():
            params.append(
                pytest.param(path.stem, rule_name, cases, id=f"{path.stem}:{rule_name}")
            )
    return params


PARAMS = _params()


def test_abnfgen_corpus_present():
    # Guard against a missing or empty corpus making the suite vacuously pass.
    assert PARAMS, f"no corpus files found under {CORPUS_DIR}"


@pytest.mark.parametrize(("module_name", "rule_name", "cases"), PARAMS)
def test_abnfgen_corpus_parses(module_name: str, rule_name: str, cases: list[str]):
    module = importlib.import_module(f"abnf.grammars.{module_name}")
    rule = module.Rule(rule_name)
    for src in cases:
        node = rule.parse_all(src)
        assert node.value == src, (
            f"{module_name}:{rule_name} did not round-trip: {src!r} -> {node.value!r}"
        )
