"""Replay the committed *negative* corpus under the active backend (issue #138).

Positive tests (``test_corpus_modules.py``) only ever feed inputs the grammar
should accept, so they cannot catch an over-permissive parser.  These negatives
close that gap: each is a valid string with one *grammar-alien* character
injected — a character no terminal of the rule can match (see
``strategy.alien_char``) — so ``parse_all`` is provably forced to reject it.

``gen_corpus.py`` builds them under the pure-Python backend and verifies each is
rejected there (raising if the parser wrongly accepts one).  Replaying under
whichever backend is active asserts the rejection holds — under a normal
``pytest`` run (rust) this is a python/rust differential on the *reject* path,
mirroring ``test_corpus_modules.py`` on the accept path.

Regenerate with ``python tests/fuzz/gen_corpus.py <module>``.
"""

import importlib
import json
import pathlib

import pytest

from abnf import ParseError

CORPUS_NEG_DIR = pathlib.Path(__file__).parent / "corpus_neg"


def _params() -> list:
    params = []
    for path in sorted(CORPUS_NEG_DIR.glob("*.json")):
        module_name = path.stem
        corpus: dict[str, list[str]] = json.loads(path.read_text(encoding="utf-8"))
        for rule_name, cases in corpus.items():
            params.append(
                pytest.param(
                    module_name, rule_name, cases, id=f"{module_name}:{rule_name}"
                )
            )
    return params


PARAMS = _params()


def test_negative_corpus_present():
    assert PARAMS, f"no negative corpus files found under {CORPUS_NEG_DIR}"


@pytest.mark.parametrize(("module_name", "rule_name", "cases"), PARAMS)
def test_negatives_are_rejected(module_name: str, rule_name: str, cases: list[str]):
    module = importlib.import_module(f"abnf.grammars.{module_name}")
    rule = module.Rule(rule_name)
    for src in cases:
        with pytest.raises(ParseError):
            rule.parse_all(src)
