"""Generate a committed acceptance corpus with abnfgen (issue #251).

``gen_corpus.py`` generates from the *built parser*: it walks the combinator
tree the loader produced and emits strings that tree accepts.  Parser and
generator are then the same object, and they agree no matter what the loader
did -- a rule built from the wrong grammar generates strings that the wrong
grammar accepts, and the corpus is green.

abnfgen reads ABNF *text*, so it is an independent oracle.  Feed it a module's
own grammar, require the module to parse everything it emits, and a
disagreement between grammar-as-written and parser-as-built has nowhere to
hide.  That is a different axis from the Hypothesis corpus, not more of it:
this one cannot check semantics the grammar text gets wrong, and that one
cannot check that the text became the parser.

Getting a module's grammar as self-contained text is the whole problem, since
imports substitute rules from other modules; see ``effective_grammar.py``.

Usage::

    python tests/fuzz/gen_abnfgen_corpus.py              # every module
    python tests/fuzz/gen_abnfgen_corpus.py rfc9051      # just this one

Requires abnfgen (http://www.quut.com/abnfgen/) on PATH, or ``ABNFGEN``
pointing at it.  Regenerate after changing a grammar module.  The committed
corpus is what CI replays, so CI needs neither abnfgen nor this script.
"""

from __future__ import annotations

import json
import os
import pathlib
import pkgutil
import shutil
import subprocess
import sys
import tempfile
from importlib import import_module

from effective_grammar import effective_grammar

import abnf.grammars

#: Samples requested per rule.  abnfgen de-duplicates nothing, so the kept
#: count is lower; the corpus is about breadth across rules, not depth.
SAMPLES_PER_RULE = 8

#: Recursion depth.  abnfgen defaults to unbounded, which on a self-embedding
#: rule produces megabyte strings that say nothing extra.  Nine rather than a
#: smaller bound because the deeper alternatives are where the interesting
#: samples live: the only surrogate-bearing case in the whole corpus needs
#: this depth to appear at all.
MAX_DEPTH = 9

#: Fixed, so regenerating an unchanged grammar produces an unchanged file.
SEED = 20250824

#: Longer candidates are dropped before parsing: parse cost is ~O(n^2) and a
#: deeply nested sample would otherwise dominate the replay.
MAX_INPUT_LEN = 400

CORPUS = pathlib.Path(__file__).parent / "corpus_abnfgen"


def abnfgen_path() -> str | None:
    return os.environ.get("ABNFGEN") or shutil.which("abnfgen")


def generate(
    abnfgen: str, grammar: pathlib.Path, rule: str, out: pathlib.Path
) -> list[str] | str:
    """Samples of ``rule``, or a message describing why abnfgen refused."""

    for stale in out.iterdir():
        stale.unlink()
    result = subprocess.run(
        [
            abnfgen,
            "-s",
            rule,
            "-r",
            str(SEED),
            "-n",
            str(SAMPLES_PER_RULE),
            "-y",
            str(MAX_DEPTH),
            "-d",
            str(out),
            "-p",
            "s#.txt",
            str(grammar),
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        return result.stderr.decode("utf-8", "replace").strip()

    samples: list[str] = []
    for path in sorted(out.iterdir()):
        raw = path.read_bytes()
        # abnfgen writes UTF-8, so %xC2 arrives as the *character* U+00C2
        # rather than as a bare byte -- which is what abnf parses, since a str
        # holds code points.
        #
        # surrogatepass, because a grammar may admit surrogates and several
        # do: rfc9116's `comment` is `"#" *(WSP / VCHAR / %x80-FFFFF)`, and
        # that range spans D800-DFFF.  abnfgen duly emits them, strict UTF-8
        # duly refuses them, and dropping those samples would silently leave
        # untested the exact code-point range issue #173 was about.
        try:
            text = raw.decode("utf-8", "surrogatepass")
        except UnicodeDecodeError:
            continue
        if len(text) <= MAX_INPUT_LEN:
            samples.append(text)
    return sorted(set(samples))


def module_corpus(name: str, abnfgen: str) -> tuple[dict[str, list[str]], list[str]]:
    module = import_module(f"{abnf.grammars.__name__}.{name}")
    text, unresolved = effective_grammar(module.Rule)

    problems = [f"{name}: undefined rule {ref}" for ref in sorted(unresolved)]
    corpus: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        grammar = root / f"{name}.abnf"
        grammar.write_text(text + "\n")
        out = root / "out"
        out.mkdir()
        for rule in sorted({rule.name for rule in module.Rule.rules()}):
            samples = generate(abnfgen, grammar, rule, out)
            if isinstance(samples, str):
                problems.append(f"{name}.{rule}: {samples}")
            elif samples:
                corpus[rule] = samples
    return corpus, problems


def module_names() -> list[str]:
    return sorted(
        name
        for _, name, _ in pkgutil.walk_packages(abnf.grammars.__path__)
        if name == "cors" or name.startswith("rfc")
    )


def main(argv: list[str]) -> int:
    abnfgen = abnfgen_path()
    if abnfgen is None:
        print(  # noqa: T201
            "abnfgen not found.  Install it from http://www.quut.com/abnfgen/ "
            "and put it on PATH, or set ABNFGEN to its location.",
            file=sys.stderr,
        )
        return 2

    CORPUS.mkdir(exist_ok=True)
    names = argv[1:] or module_names()
    problems: list[str] = []
    for name in names:
        corpus, module_problems = module_corpus(name, abnfgen)
        problems += module_problems
        cases = sum(len(v) for v in corpus.values())
        path = CORPUS / f"{name}.json"
        path.write_text(json.dumps(corpus, indent=1, sort_keys=True) + "\n")
        print(f"{name}: {cases} cases across {len(corpus)} rules -> {path}")  # noqa: T201

    if problems:
        print(f"\n{len(problems)} rules abnfgen could not generate:", file=sys.stderr)  # noqa: T201
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
