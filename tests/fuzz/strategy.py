"""Turn an ``abnf`` grammar rule into a Hypothesis strategy that emits strings
the rule accepts.

The walker introspects the pure-Python parser combinators
(``abnf._parser_python``).  It therefore requires the pure-Python backend; the
rust backend does not expose the ``.parsers`` / ``.element`` / ``.value``
attributes the walker reads.  Callers should run under ``ABNF_NO_RUST=1`` and
guard with :data:`abnf.parser._BACKEND`.

Design notes live in ``.claude/issue-138-generative-grammar-fuzz.md``.
"""

from __future__ import annotations

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from abnf._parser_python import (
    Alternation,
    Concatenation,
    Literal,
    Option,
    Prose,
    Repetition,
    Rule,
)

# Unbounded ``*`` repetition (``Repeat(min, None)``) is capped at
# ``min + MAX_EXTRA_REPEAT`` so generated strings stay bounded.  Kept small: for
# deeply recursive/composed grammars (e.g. RFC 5322 email, RFC 9051 IMAP) the
# repetition width multiplies through nesting, and parse cost is ~O(n^2) in the
# generated length, so a wide cap makes generation intractable.  min+1 still
# exercises the "more than minimal" repetition path.
MAX_EXTRA_REPEAT = 1


class UngeneratableGrammarError(Exception):
    """Raised when a rule cannot be turned into a strategy, e.g. it contains a
    ``Prose`` (``<...>``) element with no generatable content."""


def _char_case_strategy(char: str) -> SearchStrategy[str]:
    """A single-character strategy that varies letter case, so a
    case-insensitive literal exercises the parser's casefold path."""
    lower = char.lower()
    upper = char.upper()
    if lower != upper:
        return st.sampled_from([lower, upper])
    return st.just(char)


def _literal_strategy(parser: Literal) -> SearchStrategy[str]:
    value = parser.value
    if isinstance(value, tuple):
        # Inclusive character range, e.g. ('a', 'z') or ('\x80', '\xff').
        lo, hi = ord(value[0]), ord(value[1])
        return st.integers(min_value=lo, max_value=hi).map(chr)
    if value == "":
        return st.just("")
    if parser.case_sensitive:
        return st.just(value)
    # Case-insensitive literal: randomize case per character.
    return st.tuples(*(_char_case_strategy(c) for c in value)).map("".join)


def strategy_from_rule(rule: Rule) -> SearchStrategy[str]:
    """Return a strategy generating strings accepted by ``rule``.

    :raises UngeneratableGrammarError: if the rule (transitively) contains a
        ``Prose`` element.  Callers should pre-scan with :func:`has_prose` to
        skip such rules deterministically rather than relying on this.
    """

    # Memoize per rule name.  Rule references are wrapped in ``st.deferred`` so
    # recursive / mutually-recursive grammars terminate: the thunk is only
    # forced when the strategy is actually drawn from.
    memo: dict[str, SearchStrategy[str]] = {}

    def visit(parser: object) -> SearchStrategy[str]:
        if isinstance(parser, Rule):
            name = parser.name
            if name not in memo:
                memo[name] = st.deferred(lambda p=parser: visit(p.definition))
            return memo[name]
        if isinstance(parser, Alternation):
            return st.one_of([visit(p) for p in parser.parsers])
        if isinstance(parser, Concatenation):
            return st.tuples(*(visit(p) for p in parser.parsers)).map("".join)
        if isinstance(parser, Option):
            return st.one_of(st.just(""), visit(parser.alternation))
        if isinstance(parser, Repetition):
            repeat = parser.repeat
            max_size = (
                repeat.max if repeat.max is not None else repeat.min + MAX_EXTRA_REPEAT
            )
            return st.lists(
                visit(parser.element),
                min_size=repeat.min,
                max_size=max_size,
            ).map("".join)
        if isinstance(parser, Literal):
            return _literal_strategy(parser)
        if isinstance(parser, Prose):
            msg = "grammar contains a Prose (<...>) element; cannot generate"
            raise UngeneratableGrammarError(msg)
        msg = f"unhandled parser combinator: {type(parser).__name__}"
        raise UngeneratableGrammarError(msg)

    return visit(rule)


def has_prose(rule: Rule) -> bool:
    """True if ``rule`` transitively contains a ``Prose`` element (and so cannot
    be generated).  Cycle-safe."""

    seen: set[str] = set()

    def walk(parser: object) -> bool:
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


# Characters unlikely to be valid in the text grammars covered here, tried in
# order when looking for one the rule's terminals can never match.
ALIEN_CANDIDATES = ("\x00", "\x01", "\x02", "\x1f", "\x7f")


def can_match_char(rule: Rule, char: str) -> bool:
    """True if any terminal (``Literal``) reachable from ``rule`` can match
    ``char``.  Cycle-safe.  Used to construct *grammar-alien* characters for
    sound negative tests: a char for which this is False cannot appear in any
    string the rule accepts."""

    seen: set[str] = set()

    def walk(parser: object) -> bool:
        if isinstance(parser, Literal):
            value = parser.value
            if isinstance(value, tuple):
                return value[0] <= char <= value[1]
            # str literal: char can appear in a match iff it is one of its chars
            # (case-folded when the literal is case-insensitive).
            return (
                char in value
                if parser.case_sensitive
                else char.casefold() in value.casefold()
            )
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


def alien_char(rule: Rule) -> str | None:
    """A character no terminal of ``rule`` can match, or None if every candidate
    is matchable (a full-alphabet rule, e.g. one built on ``OCTET``).  Injecting
    this into an otherwise-valid string forces ``parse_all`` to reject it."""

    return next((c for c in ALIEN_CANDIDATES if not can_match_char(rule, c)), None)
