"""Generate a committed acceptance corpus for an RFC grammar module (issue #138).

Hypothesis plays the role abnfgen plays for the meta-grammar corpus: generate
inputs once, commit them, and replay them against the parser in
``test_corpus_<module>.py``.  The committed corpus is deterministic (reviewable
diffs, reproducible CI) and doubles as a permanent regression corpus, while the
live ``test_grammar_<module>.py`` suite keeps finding fresh cases.

The walker introspects the pure-Python combinators, so this script forces the
pure-Python backend by setting ``ABNF_NO_RUST=1`` *before* importing abnf —
regardless of how it is invoked.  The corpus it writes is backend-neutral; the
replay test then parses it under whichever backend is active (rust by default),
turning the corpus into a python/rust differential check.

Usage::

    python tests/fuzz/gen_corpus.py rfc7240            # all generatable rules
    python tests/fuzz/gen_corpus.py rfc7240 word token # only these rules

Regenerate after changing a grammar module (or the walker).
"""

from __future__ import annotations

import os

# Force the pure-Python backend before abnf is imported anywhere: the strategy
# walker reads combinator attributes the rust backend does not expose.
os.environ.setdefault("ABNF_NO_RUST", "1")

import importlib
import json
import pathlib
import sys

from hypothesis import given, settings
from hypothesis import strategies as st
from strategy import (
    UngeneratableGrammarError,
    alien_char,
    has_prose,
    strategy_from_rule,
)

import abnf.parser as _parser
from abnf import ParseError

# Cases generated per rule before de-duplication.
EXAMPLES_PER_RULE = 100

# Candidates longer than this are dropped *before* parsing.  parse cost is
# ~O(n^2), so an occasional pathologically long generated string (deep
# recursion) would otherwise dominate wall-clock.  Bounded inputs cover the
# grammar's structure fine; the corpus is not a stress test of input length.
MAX_INPUT_LEN = 256

# Negative cases committed per rule (grammar-alien char injected into a valid
# string; see build_negatives).
NEG_PER_RULE = 12

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
CORPUS_NEG_DIR = pathlib.Path(__file__).parent / "corpus_neg"


def _collect(strategy: st.SearchStrategy[str], count: int) -> list[str]:
    """Draw up to ``count`` examples, de-duplicated and sorted for stable diffs.

    ``derandomize=True`` makes the drawn set reproducible across regenerations,
    keeping corpus churn to a minimum.
    """
    seen: set[str] = set()

    @given(src=strategy)
    @settings(max_examples=count, derandomize=True, database=None)
    def draw(src: str) -> None:
        seen.add(src)

    draw()
    return sorted(seen)


def generate_module(
    module_name: str, rule_names: list[str] | None
) -> dict[str, list[str]]:
    module = importlib.import_module(f"abnf.grammars.{module_name}")
    rule_cls = module.Rule

    if rule_names:
        rules = [rule_cls(name) for name in rule_names]
    else:
        rules = sorted(rule_cls.rules(), key=lambda r: r.name)

    corpus: dict[str, list[str]] = {}
    for rule in rules:
        if has_prose(rule):
            print(f"  skip {rule.name}: contains Prose (<...>), not generatable")
            continue
        try:
            strategy = strategy_from_rule(rule)
        except UngeneratableGrammarError as exc:
            print(f"  skip {rule.name}: {exc}")
            continue
        candidates = _collect(strategy, EXAMPLES_PER_RULE)
        # Generate-and-filter: keep only inputs the parser actually accepts.
        # The walker generates from the grammar's *derivation* semantics, but
        # the parser uses *longest-match*; for ambiguous rules (e.g. RFC 5646
        # language-tag) a valid derivation may not be longest-match-parseable
        # as the whole rule.  Such inputs simply aren't members of the language
        # as the parser defines it, so we drop them (and report the rate).
        #
        # A parse that *succeeds* but whose value != src is a different beast:
        # that is a genuine round-trip bug, so surface it loudly rather than
        # silently dropping it.
        kept: list[str] = []
        rejected = 0
        too_long = 0
        mismatches: list[str] = []
        for src in candidates:
            if len(src) > MAX_INPUT_LEN:
                # Drop before the ~O(n^2) parse; deep recursion occasionally
                # yields a huge string that would dominate wall-clock.
                too_long += 1
                continue
            try:
                node = rule.parse_all(src)
            except ParseError:
                # Includes deeply-nested input, which the parser converts to
                # ParseError (issue #144); such inputs are simply not accepted.
                rejected += 1
                continue
            if node.value == src:
                kept.append(src)
            else:
                mismatches.append(src)
        if mismatches:
            sample = ", ".join(repr(s) for s in mismatches[:3])
            msg = (
                f"{rule.name}: {len(mismatches)} generated case(s) parsed but did "
                f"not round-trip (value != src) — likely a real bug: {sample}"
            )
            raise AssertionError(msg)
        if not kept:
            print(f"  skip {rule.name}: no generated case was accepted by the parser")
            continue
        corpus[rule.name] = kept
        notes = []
        if rejected:
            notes.append(f"{rejected} unparseable")
        if too_long:
            notes.append(f"{too_long} over {MAX_INPUT_LEN} chars")
        note = f" ({', '.join(notes)} filtered)" if notes else ""
        print(f"  {rule.name}: {len(kept)} cases{note}")

    return corpus


def build_negatives(
    module_name: str, positives: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Derive *negative* cases: inject a grammar-alien character into a valid
    string so ``parse_all`` is provably forced to reject it (no terminal can
    match the alien char).  Each negative is verified to be rejected under the
    (python) generation backend; a negative the parser *accepts* is an
    over-permissiveness bug and is raised loudly.  Rules whose alphabet spans
    every candidate char (e.g. OCTET-based) have no alien and are skipped.
    """
    module = importlib.import_module(f"abnf.grammars.{module_name}")
    rule_cls = module.Rule

    negatives: dict[str, list[str]] = {}
    accepted_bugs: list[tuple[str, str]] = []
    for rule_name, cases in positives.items():
        rule = rule_cls(rule_name)
        alien = alien_char(rule)
        if alien is None:
            continue
        seen: set[str] = set()
        for src in cases:
            # Inject at a few interior/boundary positions; skip 0 (a leading
            # alien only tests the first terminal).  End-injection leaves a
            # valid prefix with unconsumed trailing junk.
            for pos in {max(1, len(src) // 2), len(src)}:
                mutated = src[:pos] + alien + src[pos:]
                if mutated in seen:
                    continue
                seen.add(mutated)
                try:
                    rule.parse_all(mutated)
                except ParseError:
                    negatives.setdefault(rule_name, []).append(mutated)
                else:
                    accepted_bugs.append((rule_name, mutated))
                if len(negatives.get(rule_name, ())) >= NEG_PER_RULE:
                    break
            if len(negatives.get(rule_name, ())) >= NEG_PER_RULE:
                break
        if rule_name in negatives:
            negatives[rule_name] = sorted(negatives[rule_name])

    if accepted_bugs:
        sample = ", ".join(f"{r}:{s!r}" for r, s in accepted_bugs[:3])
        msg = (
            f"{len(accepted_bugs)} grammar-alien input(s) were ACCEPTED (parser "
            f"too permissive — a real bug): {sample}"
        )
        raise AssertionError(msg)
    return negatives


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    assert _parser._BACKEND == "python", (
        "generation requires the pure-Python backend; ABNF_NO_RUST was not honored"
    )

    module_name, *rule_names = argv
    print(f"generating corpus for {module_name} (backend={_parser._BACKEND})")
    corpus = generate_module(module_name, rule_names or None)

    CORPUS_DIR.mkdir(exist_ok=True)
    out_path = CORPUS_DIR / f"{module_name}.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=True, indent=1, sort_keys=True)
        f.write("\n")
    total = sum(len(v) for v in corpus.values())
    print(f"wrote {total} cases across {len(corpus)} rules -> {out_path}")

    negatives = build_negatives(module_name, corpus)
    CORPUS_NEG_DIR.mkdir(exist_ok=True)
    neg_path = CORPUS_NEG_DIR / f"{module_name}.json"
    with neg_path.open("w", encoding="utf-8") as f:
        json.dump(negatives, f, ensure_ascii=True, indent=1, sort_keys=True)
        f.write("\n")
    neg_total = sum(len(v) for v in negatives.values())
    print(f"wrote {neg_total} negatives across {len(negatives)} rules -> {neg_path}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    raise SystemExit(main(sys.argv[1:]))
