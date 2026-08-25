import gc
import json
import pathlib
import re
import subprocess
import sys
import textwrap
import threading
import warnings
import weakref
from typing import cast

import pytest

from abnf import _parser_python
from abnf import parser as _parser
from abnf.parser import (
    ABNFGrammarNodeVisitor,
    ABNFGrammarRule,
    Alternation,
    CharValNodeVisitor,
    Concatenation,
    GrammarError,
    Literal,
    LiteralNode,
    Match,
    Node,
    NodeVisitor,
    NumValVisitor,
    Option,
    ParseCache,
    ParseError,
    Parser,
    Prose,
    Repeat,
    Repetition,
    Rule,
    next_longest,
    sorted_by_longest_match,
)


def test_sorted_by_longest_match():
    match0 = Match([], 0)
    match1 = Match([], 1)
    match2 = Match([], 2)
    assert sorted_by_longest_match([match0, match1, match2]) == [match2, match1, match0]


def test_next_longest():
    match0 = Match([], 0)
    match1 = Match([], 1)
    match2 = Match([], 2)
    assert list(next_longest({match0, match1, match2})) == [
        match2,
        match1,
        match0,
    ]


# ---------------------------------------------------------------------------
# Match equality and hashing are used by callers, not by the parser -- both
# Repetition and Rule.lparse deduplicate by end offset -- so nothing else in
# the suite would notice these regressing.
# ---------------------------------------------------------------------------


def test_match_equality_is_by_value_and_end_offset():
    ab = Match([cast(Node, LiteralNode("ab", 0, 2))], 2)
    a_b = Match(
        [cast(Node, LiteralNode("a", 0, 1)), cast(Node, LiteralNode("b", 1, 1))], 2
    )
    # Same text, same end: equal whatever node structure produced it.  An
    # ambiguous grammar can reach one span several ways and the parser treats
    # those as a single result.
    assert ab == a_b
    assert hash(ab) == hash(a_b)

    # Same text, different end position.
    assert ab != Match([cast(Node, LiteralNode("ab", 0, 2))], 3)
    # Different text, same end position.
    assert ab != Match([cast(Node, LiteralNode("xy", 0, 2))], 2)


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND == "rust",
    reason="Forcing a hash collision needs a subclass, and the Rust Match "
    "pyclass cannot be subclassed.  The dispatch shim rebinds Match inside "
    "_parser_python too, so the pure-Python class is unreachable here.",
)
def test_match_equality_does_not_rely_on_hash_equality():
    # `__eq__` compares the values themselves.  Hash equality is only
    # evidence of equality, so two matches that collided must still compare
    # unequal.
    class CollidingMatch(Match):
        __slots__ = ()

        def __hash__(self) -> int:
            return 0

    left = CollidingMatch([cast(Node, LiteralNode("a", 0, 1))], 1)
    right = CollidingMatch([cast(Node, LiteralNode("b", 0, 1))], 1)
    assert hash(left) == hash(right)
    assert left != right


def test_match_is_usable_in_a_set():
    ab = Match([cast(Node, LiteralNode("ab", 0, 2))], 2)
    same = Match(
        [cast(Node, LiteralNode("a", 0, 1)), cast(Node, LiteralNode("b", 1, 1))], 2
    )
    other = Match([cast(Node, LiteralNode("ab", 0, 2))], 3)
    assert len({ab, same, other}) == 2


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND == "rust",
    reason="The Rust Match hands back a fresh `nodes` list on each access, so "
    "mutating it never reaches the match; the stale-memo question this pins "
    "is specific to the pure-Python class, whose `nodes` is the live list.",
)
def test_match_hash_tracks_mutation():
    # No memo, so a hash cannot go stale: `nodes` is the live list and a
    # caller who edits it gets a hash for what the match now holds.
    match = Match([cast(Node, LiteralNode("a", 0, 1))], 1)
    before = hash(match)
    match.nodes.append(cast(Node, LiteralNode("b", 1, 1)))
    assert hash(match) != before


def test_match_str():
    match = Match([], 0)
    assert str(match)


def test_oarse_cache_bad_max_size():
    with pytest.raises(ValueError):
        ParseCache(-12)


def test_oarse_cache_miss():
    cache = ParseCache()
    with pytest.raises(KeyError):
        cache[("foo", 1)]
    assert cache.misses == 1


def test_cache_hit():
    cache = ParseCache()
    match_set = {Match([], 0)}
    cache[("foo", 1)] = match_set
    assert len(cache) == 1
    assert cache[("foo", 1)] == match_set
    assert cache.hits == 1
    assert cache.misses == 0


def test_parse_cache_max_size():
    cache = ParseCache(max_size=1)
    cache[("foo", 1)] = {Match([], 0)}
    assert len(cache) == 1
    match_set = {Match([], 2)}
    cache[("foo", 3)] = match_set
    assert len(cache) == 1
    assert cache[("foo", 3)] == match_set


def test_parse_cache_del_item():
    cache = ParseCache(max_size=1)
    cache[("foo", 1)] = {Match([], 0)}
    assert len(cache) == 1
    del cache[("foo", 1)]
    assert len(cache) == 0
    cache = ParseCache()
    cache[("foo", 1)] = {Match([], 0)}


def test_parse_cache_iter():
    cache = ParseCache()
    cache[("foo", 1)] = {Match([], 0)}
    assert list(cache) == [("foo", 1)]


def test_parse_cache_eq():
    cache = ParseCache()
    assert cache == cache


def test_parse_cache_not_eq():
    cache1 = ParseCache()
    cache2 = ParseCache()
    assert cache1 != cache2


def test_parse_cache_str():
    assert str(ParseCache())


def test_parse_cache_clear_caches():
    cache = ParseCache()
    cache[("foo", 1)] = {Match([], 0)}
    cache[("foo", 1)]  # trigger a hit
    try:  # noqa: SIM105
        cache[("bar", 1)]  # trigger a miss
    except KeyError:
        pass

    # Deprecated: the parser no longer holds a ParseCache, so this clears only
    # caches the caller made.  It still has to do that much.
    with pytest.deprecated_call():
        ParseCache.clear_caches()
    for c in ParseCache.list():
        assert len(c) == 0
        assert c.misses == 0
        assert c.hits == 0


def test_parse_cache_max_cache_size_assignment_is_deprecated():
    original = ParseCache.max_cache_size
    try:
        with pytest.deprecated_call():
            ParseCache.max_cache_size = 1024
    finally:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ParseCache.max_cache_size = original


# ---------------------------------------------------------------------------
# H1: the parse memo is scoped to one parse, so a grammar mutated between
# parses can never be observed through a stale cached result.  Each of these
# returned the pre-mutation answer while the cache was per-Repetition and
# keyed (source, start) with no invalidation.
# ---------------------------------------------------------------------------


def test_h1_incremental_definition_is_not_masked_by_a_stale_cache():
    class IncrementalRule(Rule):
        pass

    IncrementalRule.create('inner = "a"')
    IncrementalRule.create("word = 1*inner")
    with pytest.raises(ParseError):
        IncrementalRule("word").parse_all("ab")  # caches the failure

    IncrementalRule.create('inner =/ "b"')  # grammar now accepts "ab"
    assert IncrementalRule("word").parse_all("ab").value == "ab"


def test_h1_exclude_rule_is_not_masked_by_a_stale_cache():
    class ExcludeAfterParseRule(Rule):
        pass

    ExcludeAfterParseRule.create("ident = 1*%x61-7A")
    ExcludeAfterParseRule.create('kw = "foo"')
    ExcludeAfterParseRule.create('phrase = 1*(ident ".")')
    assert ExcludeAfterParseRule("phrase").parse_all("foo.")  # warms the cache

    ExcludeAfterParseRule("ident").exclude_rule(ExcludeAfterParseRule("kw"))
    with pytest.raises(ParseError):
        ExcludeAfterParseRule("phrase").parse_all("foo.")


def test_h1_first_match_alternation_is_not_masked_by_a_stale_cache():
    class FirstMatchAfterParseRule(Rule):
        pass

    FirstMatchAfterParseRule.create('inner = "ab" / "abc"')
    FirstMatchAfterParseRule.create("outer = 1*inner")
    _, longest = FirstMatchAfterParseRule("outer").parse("abcab", 0)
    assert longest == 5

    FirstMatchAfterParseRule("inner").first_match_alternation = True
    _, first = FirstMatchAfterParseRule("outer").parse("abcab", 0)
    assert first == 2


def test_parse_memo_does_not_outlive_the_parse():
    class MemoScopeRule(Rule):
        pass

    MemoScopeRule.create("s = 1*%x61-7A")
    MemoScopeRule("s").parse_all("abc")
    # Nothing is bound once the parse returns, so nothing is retained.
    assert _parser_python._parse_memo.get() is None


def test_nested_parse_restores_the_outer_memo():
    # Rule.lparse runs exclude.parse_all on a *different* source mid-parse.
    # The inner parse must bind its own memo and hand the outer one back,
    # otherwise the outer parse would key positions against the wrong source.
    class NestedParseRule(Rule):
        pass

    NestedParseRule.create("ident = 1*%x61-7A")
    NestedParseRule.create('kw = "foo"')
    NestedParseRule.create('phrase = 1*(ident ".")')
    NestedParseRule("ident").exclude_rule(NestedParseRule("kw"))

    assert NestedParseRule("phrase").parse_all("bar.")
    with pytest.raises(ParseError):
        NestedParseRule("phrase").parse_all("foo.")
    assert _parser_python._parse_memo.get() is None


# ---------------------------------------------------------------------------
# #179: exclusions must apply to nested rule references, not only to whichever
# rule the caller parses directly.  The Rust engine resolves rule references
# internally and enters the pure-Python Rule.lparse just once per parse, so
# before the bridge forwarded exclusions it silently accepted what the grammar
# was written to reject.
# ---------------------------------------------------------------------------


def _keyword_grammar():
    class KeywordGrammar(Rule):
        pass

    KeywordGrammar.create("ident = 1*%x61-7A")
    KeywordGrammar.create('kw = "foo"')
    KeywordGrammar.create('phrase = 1*(ident ".")')
    KeywordGrammar("ident").exclude_rule(KeywordGrammar("kw"))
    return KeywordGrammar


def test_179_exclusion_applies_to_nested_rule_references():
    grammar = _keyword_grammar()
    with pytest.raises(ParseError):
        grammar("phrase").parse_all("foo.")


def test_179_exclusion_leaves_other_input_alone():
    grammar = _keyword_grammar()
    assert grammar("phrase").parse_all("bar.").value == "bar."


def test_179_partial_match_does_not_exclude():
    # The Python side runs `parse_all` over the matched value, so only a
    # complete match disqualifies: "foobar" is not the keyword "foo".
    grammar = _keyword_grammar()
    assert grammar("ident").parse_all("foobar").value == "foobar"


def test_179_exclusion_can_be_replaced():
    class ReplaceExcludeGrammar(Rule):
        pass

    ReplaceExcludeGrammar.create("ident = 1*%x61-7A")
    ReplaceExcludeGrammar.create('kw = "foo"')
    ReplaceExcludeGrammar.create('other = "bar"')
    ReplaceExcludeGrammar("ident").exclude_rule(ReplaceExcludeGrammar("kw"))
    ReplaceExcludeGrammar("ident").exclude_rule(ReplaceExcludeGrammar("other"))

    assert ReplaceExcludeGrammar("ident").parse_all("foo").value == "foo"
    with pytest.raises(ParseError):
        ReplaceExcludeGrammar("ident").parse_all("bar")


def _nested_keyword_grammar():
    """`ident` appears only *inside* `phrase`, so the exclusion is
    exercised through a nested reference -- the case the Rust engine
    used to ignore, and the only one that tells the backends apart."""

    class NestedKeywordGrammar(Rule):
        pass

    NestedKeywordGrammar.create("ident = 1*%x61-7A")
    NestedKeywordGrammar.create('kw = "foo"')
    NestedKeywordGrammar.create('phrase = 1*(ident ".")')
    return NestedKeywordGrammar


def test_179_exclusion_is_cleared_by_assigning_none():
    grammar = _nested_keyword_grammar()
    grammar("ident").exclude_rule(grammar("kw"))
    with pytest.raises(ParseError):
        grammar("phrase").parse_all("foo.")

    # `exclude` is a property whose setter notifies the backend, so
    # clearing works through the attribute as well as the method.
    grammar("ident").exclude = None
    assert grammar("phrase").parse_all("foo.").value == "foo."


def test_179_exclusion_can_be_set_by_assigning_the_attribute():
    grammar = _nested_keyword_grammar()
    grammar("ident").exclude = grammar("kw")
    with pytest.raises(ParseError):
        grammar("phrase").parse_all("foo.")


def test_179_excluding_an_undefined_rule_is_a_grammar_error():
    # Not "the input did not match": the grammar names a rule that was
    # never defined, which both backends must report as such rather
    # than quietly accepting the input.
    grammar = _nested_keyword_grammar()
    grammar("ident").exclude_rule(grammar("never-defined"))
    with pytest.raises(GrammarError):
        grammar("phrase").parse_all("foo.")


def test_parseerror_str():
    # I'm not checking the output, just exercising ParseError.__str__ .
    assert str(ParseError(Literal("a"), 1))


def test_backtracking():
    src = "aababb"
    parser = Concatenation(
        Repetition(Repeat(), Alternation(Literal("a"), Literal("b"))), Literal("b")
    )
    result = parser.lparse(src, 0)
    match = next(result)
    assert "".join(n.value for n in match.nodes) == src


def test_deeply_nested_input_does_not_leak_recursionerror():
    """Regression for issues #144 and #170: deeply-nested input must not escape
    as an uncaught RecursionError, and must not take the process down either.
    Both backends convert it to ParseError -- the pure-Python one from CPython's
    recursion limit, the Rust one from its stack budget (which surfaces as
    RecursionError and is converted by `Rule.parse` on the way out)."""

    class DeepGrammar(Rule):
        pass

    DeepGrammar.create('nested = "(" [ nested ] ")"')
    depth = 1000
    src = "(" * depth + ")" * depth

    raised_parse_error = False
    try:
        DeepGrammar("nested").parse_all(src)
    except ParseError:
        raised_parse_error = True
    # RecursionError is not caught here, so if the fix regresses it propagates
    # and fails the test.

    # Before #170 the Rust backend parsed this successfully on Linux and macOS
    # and killed the interpreter on Windows.  Neither is right: the depth is
    # pathological and the answer is the same catchable error everywhere.
    assert raised_parse_error


def test_alternation_first_match():
    parser = Alternation(Literal("a"), Literal("ab"), first_match=True)
    result = parser.lparse("ab", 0)
    match = next(result)
    assert "".join(n.value for n in match.nodes) == "a"
    assert match.start == 1


def test_alternation_fail():
    parser = Alternation(Literal("a"), Literal("b"))
    result = parser.lparse("c", 0)
    with pytest.raises(ParseError):
        next(result)


def test_alternation_str():
    assert str(Alternation(Literal("a"), Literal("b")))


def test_concatenation_str():
    assert str(Concatenation(Literal("a")))


def test_repeat_str():
    assert str(Repeat())


def test_repetition_str():
    assert str(Repetition(Repeat(1, 2), Literal("foo")))


# ---------------------------------------------------------------------------
# X4: `min*max` with max < min is an impossible range.  Unvalidated it
# silently behaves as `min*` -- `3*2"a"` rejected "aa" but accepted "aaa",
# "aaaa", ... -- so a typo for `2*3` became unbounded repetition with no
# diagnostic.  Both backends must reject it identically.
# ---------------------------------------------------------------------------


def test_x4_repeat_max_less_than_min_raises():
    with pytest.raises(GrammarError):
        Repeat(3, 2)


def test_x4_repeat_max_equal_to_min_is_fine():
    # The boundary is legal: `2*2` is an exact count, spelled `2` in ABNF.
    assert str(Repeat(2, 2))


def test_x4_impossible_repetition_rejected_at_grammar_load():
    class BadRepeatRule(Rule):
        pass

    with pytest.raises(GrammarError):
        BadRepeatRule.create('s = 3*2"a"')


def test_x4_ordinary_repetition_bounds_still_load():
    class GoodRepeatRule(Rule):
        pass

    GoodRepeatRule.create('s = 2*3"a"')
    assert GoodRepeatRule("s").parse_all("aa")
    assert GoodRepeatRule("s").parse_all("aaa")
    with pytest.raises(ParseError):
        GoodRepeatRule("s").parse_all("aaaa")


# ---------------------------------------------------------------------------
# X2: `start` was never validated.  A negative value is a valid Python slice
# measured from the end of the source, so `parse("abcdef", -4)` matched "cd"
# and returned negative node offsets, while the Rust backend raised
# OverflowError -- the backends disagreed on a case where neither was right.
# ---------------------------------------------------------------------------


class StartRule(Rule):
    pass


StartRule.create('mid = "cd"')
StartRule.create("one = %x61-7A")


@pytest.mark.parametrize("start", [-1, -4, -99])
def test_x2_negative_start_rejected(start: int):
    with pytest.raises(ValueError, match="start must be in"):
        StartRule("mid").parse("abcdef", start)


@pytest.mark.parametrize("start", [7, 99])
def test_x2_start_past_end_rejected(start: int):
    with pytest.raises(ValueError, match="start must be in"):
        StartRule("mid").parse("abcdef", start)


def test_x2_start_at_end_of_source_is_allowed():
    # len(source) is a legal position -- there is simply nothing to match
    # there, which is a ParseError rather than a programming error.
    with pytest.raises(ParseError):
        StartRule("mid").parse("abcdef", 6)


def test_x2_valid_start_still_parses():
    node, start = StartRule("mid").parse("abcdef", 2)
    assert node.value == "cd"
    assert start == 4


def test_x2_bool_start_is_normalised_to_int():
    # bool is an int subclass, so `True` was used as an index but arrived
    # verbatim in ParseError.start on the Python backend while the Rust
    # backend reported 1.  operator.index normalises it.
    with pytest.raises(ParseError) as excinfo:
        StartRule("mid").parse("abcdef", True)
    assert excinfo.value.start == 1
    assert not isinstance(excinfo.value.start, bool)


@pytest.mark.parametrize("start", [1.5, None, "2"])
def test_x2_non_integer_start_rejected(start: object):
    with pytest.raises(TypeError, match="cannot be interpreted as an integer"):
        StartRule("mid").parse("abcdef", start)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Surrogate code points (issue #173).  A Python `str` may hold a lone
# surrogate and ABNF may name one (`%xD800-DBFF`), so both are part of the
# domain this library parses.  They used to be the one place the backends
# disagreed: the Rust engine worked in `char`/`&str` -- Unicode *scalar
# values* and well-formed UTF-8 -- which cannot represent a surrogate, so a
# grammar naming one failed to load and input containing one failed to cross
# the FFI.  The engine now indexes by code point, so both work.
#
# This is ordinary input, not a curiosity: `surrogateescape` is how Python
# represents undecodable filenames, `sys.argv` and environment variables on
# POSIX, and an unpaired \uD800 survives `json.loads`.
# ---------------------------------------------------------------------------

_SURROGATE_SOURCE = b"caf\xe9".decode("utf-8", "surrogateescape")


def test_173_grammar_may_name_surrogates():
    class SurrogateGrammar(Rule):
        pass

    SurrogateGrammar.create("s = %xD800-DBFF")
    node = SurrogateGrammar("s").parse_all("\ud800")
    assert node.value == "\ud800"

    with pytest.raises(ParseError):
        SurrogateGrammar("s").parse_all("\udc00")


def test_173_surrogate_input_parses():
    class SurrogateInputGrammar(Rule):
        pass

    SurrogateInputGrammar.create("s = 1*%x00-10FFFF")
    node = SurrogateInputGrammar("s").parse_all(_SURROGATE_SOURCE)
    assert node.value == _SURROGATE_SOURCE
    assert len(node.value) == 4


def test_173_surrogate_literal_round_trips():
    """A literal may itself be a surrogate, and the node value that comes
    back must be the same code point rather than a replacement char."""

    class SurrogateLiteral(Rule):
        pass

    SurrogateLiteral.create("s = %xD800 %x61")
    node = SurrogateLiteral("s").parse_all("\ud800a")
    assert node.value == "\ud800a"
    literals = [n for n in node.children if hasattr(n, "offset")]
    assert [n.value for n in literals] == ["\ud800", "a"] or node.value == "\ud800a"


def test_173_offsets_are_code_points_with_surrogates_present():
    """The offset contract is code points, and a surrogate is one code
    point -- not the two a UTF-16 view or the three a UTF-8 view would
    suggest."""

    class SurrogateOffsets(Rule):
        pass

    SurrogateOffsets.create('s = %xD800-DFFF "x"')
    node = SurrogateOffsets("s").parse_all("\ud800x")
    literals = _literal_nodes(node)
    assert [(n.offset, n.length) for n in literals] == [(0, 1), (1, 1)]


def test_173_callback_parser_inside_an_exclusion_gets_the_matched_span():
    """An exclusion sub-parse runs over a *slice* of the source.  The
    engine holds code points, so handing that slice to an embedded
    Python parser means rebuilding a `str` for it -- and it must be the
    slice, not the whole source."""
    seen: list[tuple[str, int]] = []

    class Spy:
        def lparse(self, source, start):
            seen.append((source, start))
            if source.startswith("stop", start):
                yield Match([cast(Node, LiteralNode("stop", start, 4))], start + 4)
            else:
                raise ParseError(self, start)

    class ExcludeCallback(Rule):
        pass

    ExcludeCallback.create("word = 1*%x61-7A")
    ExcludeCallback("kw", cast(Parser, Spy()))
    ExcludeCallback("word").exclude = ExcludeCallback("kw")

    assert ExcludeCallback("word").parse_all("go").value == "go"
    with pytest.raises(ParseError):
        ExcludeCallback("word").parse_all("stop")
    assert [s for s, _ in seen] == ["go", "stop", "sto"]


def test_173_surrogates_survive_the_callback_round_trip():
    """The rebuilt `str` goes through UTF-32/surrogatepass, the one
    limited-API decoder that round-trips a lone surrogate."""
    seen: list[str] = []

    class Spy:
        def lparse(self, source, start):
            seen.append(source)
            raise ParseError(self, start)

    class SurrogateCallback(Rule):
        pass

    SurrogateCallback.create("any = 1*%x00-10FFFF")
    SurrogateCallback("sur", cast(Parser, Spy()))
    SurrogateCallback("any").exclude = SurrogateCallback("sur")

    source = "a\ud800b"
    assert SurrogateCallback("any").parse_all(source).value == source
    assert seen and all("\ud800" in s for s in seen)


def test_173_parse_may_re_enter_from_a_callback_parser():
    """The code-point buffer is pooled per thread, so a callback that
    starts another parse mid-parse must not disturb the outer one."""

    class Digits(Rule):
        pass

    Digits.create("digits = 1*%x30-39")

    class Nested:
        def lparse(self, source, start):
            assert Digits("digits").parse_all("12345").value == "12345"
            if start < len(source):
                yield Match(
                    [cast(Node, LiteralNode(source[start], start, 1))], start + 1
                )
            else:
                raise ParseError(self, start)

    class OuterRule(Rule):
        pass

    OuterRule(
        "host",
        Concatenation(Literal("<"), cast(Parser, Nested()), Literal(">")),
    )
    assert OuterRule("host").parse_all("<é>").value == "<é>"


def test_173_concurrent_parses_do_not_share_a_buffer():
    class Threaded(Rule):
        pass

    Threaded.create("digits = 1*%x30-39")
    errors: list[BaseException] = []

    def worker(text: str) -> None:
        try:
            for _ in range(100):
                assert Threaded("digits").parse_all(text).value == text
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(str(i) * 20,)) for i in range(1, 6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors


def _literal_nodes(node):
    out = []
    if hasattr(node, "offset"):
        out.append(node)
    for child in getattr(node, "children", None) or ():
        out.extend(_literal_nodes(child))
    return out


def test_option_str():
    assert str(Option(Literal("foo")))


def test_literal():
    parser = Literal("a")
    matches = parser.lparse("a", 0)
    match = next(matches)
    assert match == Match([cast(Node, LiteralNode("a", 0, 1))], 1)


def test_literal_bad_arg():
    with pytest.raises(TypeError):
        Literal(("x", 1))  # type: ignore


class FMARule(Rule):
    pass


def test_rule_first_match_alternation_get():
    rule = FMARule("test-first-match-alternation")
    assert rule.first_match_alternation is False
    rule.definition = Alternation(Literal("a"), Literal("ab"))
    assert rule.first_match_alternation is False


def test_rule_first_match_alternation_set():
    rule = FMARule("test-first-match-alternation")
    assert rule.first_match_alternation is False
    node, start = rule.parse("ab", 0)
    assert node.value == "ab"
    assert start == 2
    rule.first_match_alternation = True
    assert rule.first_match_alternation is True
    node, start = rule.parse("ab", 0)
    assert node.value == "a"
    assert start == 1
    rule.first_match_alternation = False
    assert rule.first_match_alternation is False
    node, start = rule.parse("ab", 0)
    assert node.value == "ab"
    assert start == 2


def test_rule_first_match_alternation_grammar_error():
    rule = FMARule("no-grammar")
    with pytest.raises(GrammarError):
        rule.first_match_alternation = False


def test_rule_first_match_alternation_pass():
    # this test just exercises first_match_alternation setter
    # in the case of a rule which is not an alternation.
    rule = FMARule("no-alternation", Literal("a"))
    rule.first_match_alternation = True


def test_rule_grammar_error():
    with pytest.raises(GrammarError):
        FMARule("no-definition").parse("a", 0)


class ExcludeRule(Rule):
    pass


ExcludeRule.create("foo = %x66.6f.6f")
ExcludeRule.create("keyword = foo")
ExcludeRule.create("identifier = ALPHA *(ALPHA / DIGIT )")


def test_exclusion():
    identifier = ExcludeRule("identifier")
    identifier.exclude_rule(ExcludeRule("keyword"))
    assert identifier.parse_all("foobar")
    with pytest.raises(ParseError):
        identifier.parse_all(
            "foo"
        )  # this will match 'fo', perhaps because of backtrackery.
        # so we want a different test to trigger the parse error.


def test_exclusion_2():
    identifier = ExcludeRule("identifier")
    identifier.exclude_rule(ExcludeRule("keyword"))
    node, start = identifier.parse("foo", 0)
    # thanks to backtracking, we get this match.
    assert node.value == "fo"
    assert start == 2


def test_exclusion_3():
    identifier_initial = ExcludeRule.create("identifier-initial = ALPHA")
    no_a_initial = ExcludeRule.create('no-a-initial = "a"')
    identifier_initial.exclude_rule(no_a_initial)
    with pytest.raises(ParseError):
        identifier_initial.parse("a", 0)


def test_rule_str():
    assert str(Rule("DIGIT"))


def test_rule_from_file(tmp_path: pathlib.Path):
    grammar = ['foo = "foo"\r\n', 'bar = "bar"\r\n']
    path = tmp_path / "test_grammar.abnf"
    path.write_text("".join(grammar))

    class FromFileRule(Rule):
        pass

    FromFileRule.from_file(path)


def test_node_str():
    node = Node("test")
    assert str(node)


def test_node_eq():
    assert Node("test") == Node("test")


def test_literal_node_children():
    assert LiteralNode("a", 0, 1).children == []


def test_literal_node_str():
    assert str(LiteralNode("a", 0, 1))


def test_literal_node_eq():
    assert LiteralNode("a", 0, 1) == LiteralNode("a", 0, 1)


def test_literal_node_neq():
    assert LiteralNode("a", 0, 1) != LiteralNode("a", 1, 1)


def test_bin_val():
    src = "b01111000"
    node = ABNFGrammarRule("bin-val").parse_all(src)
    visitor = NumValVisitor()
    parser = visitor.visit(node)
    assert parser.value == "x"


def test_prose_val():
    class ProseRule(Rule):
        pass

    src = "<blah blah>"
    node = ABNFGrammarRule("prose-val").parse_all(src)
    visitor = ABNFGrammarNodeVisitor(ProseRule)
    parser = visitor.visit(node)
    assert isinstance(parser, Prose)


def test_prose():
    with pytest.raises(ParseError):
        Prose().lparse("<blah blah>", 0)


class EdgeCaseRule(Rule):
    pass


EdgeCaseRule.create('repeat-a = *"a"')
EdgeCaseRule.create('repeat-repeat-a = *(*"a")')


def test_repetition():
    node, start = EdgeCaseRule("repeat-a").parse("", 0)
    assert node.value == ""
    assert start == 0


def test_repetition_1():
    node, start = EdgeCaseRule("repeat-repeat-a").parse("", 0)
    assert node.value == ""
    assert start == 0


def test_repetition_2():
    result = Repetition(Repeat(0, 0), Literal("*")).lparse("***", 0)
    matches = list(result)
    assert len(matches) == 1
    match = matches[0]
    assert match.nodes == []
    assert match.start == 0


def test_repetition_3():
    result = Repetition(Repeat(0, 1), Literal("*")).lparse("***", 0)
    matches = list(result)
    assert matches == [
        Match(nodes=[cast(Node, LiteralNode("*", 0, 1))], start=1),
        Match(nodes=[], start=0),
    ]


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND == "rust",
    reason="Repetition's parse cache is internal to the Rust engine; "
    "the pure-Python lparse_cache attribute is not exposed by the "
    "Rust-backed pyclass.",
)
def test_repetition_cached_oarseerror():
    src = "a"
    parser = Repetition(Repeat(1, 1), Literal("*"))
    # Populate the cache by triggering a real failure.
    with pytest.raises(ParseError) as first:
        next(parser.lparse(src, 0))
    # A second call should re-raise from the cache, but as a *fresh*
    # ParseError instance (not the same object) so that tracebacks
    # don't accumulate on a shared exception.
    with pytest.raises(ParseError) as second:
        next(parser.lparse(src, 0))
    assert second.value is not first.value
    assert second.value.parser is first.value.parser
    assert second.value.start == first.value.start


# ---------------------------------------------------------------------------
# NodeVisitor dispatch: the visit_* table is cached per class rather than
# rebuilt from dir(self) per instance.  Everything the old behaviour supported
# still has to work, including the dynamic cases the library itself depends on.
# ---------------------------------------------------------------------------


def test_visitor_dispatches_to_class_methods():
    class ClassMethodVisitor(NodeVisitor):
        def visit_alpha(self, node):
            return "alpha"

    assert ClassMethodVisitor().visit(Node("alpha")) == "alpha"
    assert ClassMethodVisitor().visit(Node("unknown")) is None


def test_visitor_dispatches_to_instance_attributes():
    # ABNFGrammarNodeVisitor assigns self.visit_char_val / self.visit_num_val
    # before calling super().__init__(), specifically so they are picked up.
    class InstanceAttrVisitor(NodeVisitor):
        def __init__(self):
            self.visit_beta = lambda node: "beta"
            super().__init__()

    assert InstanceAttrVisitor().visit(Node("beta")) == "beta"


def test_visitor_sees_methods_added_to_the_class_afterwards():
    # The old implementation rebuilt from dir(self) on every instantiation, so
    # a method added later took effect.  The cache must not change that.
    class LateMethodVisitor(NodeVisitor):
        def visit_alpha(self, node):
            return "alpha"

    LateMethodVisitor()  # populates the cache
    setattr(LateMethodVisitor, "visit_gamma", lambda self, node: "gamma")  # noqa: B010
    assert LateMethodVisitor().visit(Node("gamma")) == "gamma"

    delattr(LateMethodVisitor, "visit_gamma")
    assert LateMethodVisitor().visit(Node("gamma")) is None


def test_visitor_subclass_table_is_independent_of_its_parent():
    class ParentVisitor(NodeVisitor):
        def visit_alpha(self, node):
            return "alpha"

    class ChildVisitor(ParentVisitor):
        def visit_delta(self, node):
            return "delta"

    ParentVisitor()  # cache the parent's table first
    assert ChildVisitor().visit(Node("delta")) == "delta"
    assert ChildVisitor().visit(Node("alpha")) == "alpha"
    # The child's extra method must not leak upwards.
    assert ParentVisitor().visit(Node("delta")) is None


def test_visitor_normalises_node_names():
    class HyphenVisitor(NodeVisitor):
        def visit_addr_spec(self, node):
            return "addr-spec"

    # Node names are hyphenated and case-insensitive in ABNF.
    assert HyphenVisitor().visit(Node("addr-spec")) == "addr-spec"
    assert HyphenVisitor().visit(Node("ADDR-SPEC")) == "addr-spec"


def test_empty_charval_node():
    # CharValNodeVisitor was incorrectly skipping literal nodes with value "".
    # https://github.com/declaresub/abnf/issues/14
    node = ABNFGrammarRule("char-val").parse_all('""')
    visitor = CharValNodeVisitor()
    parser = visitor.visit(node)
    assert parser


def test_load_grammar_not_strict():
    class NotStrictGrammarRule(Rule):
        pass

    grammar = 'foo = "foo"\r\n'
    NotStrictGrammarRule.load_grammar(grammar, strict=False)
    assert NotStrictGrammarRule("foo").definition


# ---------------------------------------------------------------------------
# H4 regression: byte vs code-point offsets at the Python/Rust boundary
# ---------------------------------------------------------------------------
#
# `Match.start` and `ParseError.start` are documented as code-point offsets
# (so they index a Python `str` correctly).  The Rust engine uses byte
# offsets internally; the FFI layer must translate at the boundary.
# These tests exercise that translation with non-ASCII source where bytes
# and code points diverge.  All four pass under the pure-Python backend
# and must continue to pass under the Rust backend.


def test_h4_match_start_is_codepoint_on_non_ascii():
    """Outbound: `Match.start` must be a code-point offset."""
    parser = Literal("é")  # 1 code point, 2 UTF-8 bytes
    source = "éY"
    match = next(parser.lparse(source, 0))
    assert match.start == 1
    assert source[match.start] == "Y"


def test_h4_match_start_with_multi_codepoint_non_ascii():
    """Outbound, longer pattern, to rule out a coincidental 1."""
    parser = Literal("éé")  # 2 code points, 4 UTF-8 bytes
    source = "ééX"
    match = next(parser.lparse(source, 0))
    assert match.start == 2
    assert source[match.start] == "X"


def test_h4_lparse_start_arg_is_codepoint_on_non_ascii():
    """Inbound: a `start` argument passed from Python is a code-point
    offset and must be translated to a byte offset before the Rust
    engine indexes into the source."""
    parser = Literal("X")
    source = "ééX"  # 'X' is at code-point 2, byte 4
    match = next(parser.lparse(source, 2))
    assert "".join(n.value for n in match.nodes) == "X"
    assert match.start == 3


def test_h4_parse_all_detects_partial_consumption_with_non_ascii():
    """`Rule.parse_all` raises when not all source is consumed; the
    check is `start < len(source)` where `len` counts code points,
    so `start` (returned from the engine through `Rule.parse`) must
    also be in code points.  If `start` is a byte count, an unparsed
    trailing ASCII suffix can be missed entirely.

    Rule is built programmatically — ABNF source is ASCII-only by spec,
    so we can't express a non-ASCII literal via `Rule.create`."""

    class G(Rule):
        pass

    G("test", Literal("éé"))  # 2 code points, 4 bytes
    with pytest.raises(ParseError):
        G("test").parse_all("ééX")  # 3 code points, 5 bytes — trailing X is unparsed


def test_h4_parse_error_start_is_codepoint_on_non_ascii():
    """`ParseError.start` raised by `parse_all` must be a code-point
    offset so users can index back into their `str` source."""

    class G(Rule):
        pass

    G("test", Literal("éé"))
    source = "ééX"
    with pytest.raises(ParseError) as exc_info:
        G("test").parse_all(source)
    assert exc_info.value.start == 2
    assert source[exc_info.value.start] == "X"


# ---------------------------------------------------------------------------
# X3: case-insensitive matching folds over US-ASCII only.  RFC 5234 §2.3
# makes literals case-insensitive and fixes their character set as
# US-ASCII, so case-insensitivity is defined over ASCII and nothing else.
#
# Until 2.8.1 both backends used full Unicode folding (Python's
# `str.casefold()`, the `caseless` crate in Rust), which over-accepted:
# an ASCII grammar matched '\u017f' (long s) against "s" and '\u212a'
# (Kelvin sign) against "k", so e.g. RFC 7230 accepted 'compre\u017f\u017f'
# as a transfer-coding.  Against a peer that folds only ASCII, that is a
# parser differential.
#
# Unicode folding is also not length-preserving, which made matching
# position-dependent: Literal("ss") matched a lone 'ß' but not the 'ß' in
# "ßx", because the comparison folds a fixed-width window of the source.
# ASCII folding removes both problems.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, source",
    [
        ("ss", "ß"),  # 'ß'.casefold() == 'ss'
        ("SS", "ß"),
        ("ffi", "\ufb03"),  # 'ﬃ'.casefold() == 'ffi'
        ("s", "\u017f"),  # LATIN SMALL LETTER LONG S
        ("k", "\u212a"),  # KELVIN SIGN
        ("K", "\u212a"),
    ],
)
def test_x3_case_insensitive_does_not_fold_non_ascii(pattern, source):
    """Non-ASCII source must not match an ASCII pattern, in either
    direction of case."""
    parser = Literal(pattern, case_sensitive=False)
    with pytest.raises(ParseError):
        next(parser.lparse(source, 0))


def test_x3_case_insensitive_still_folds_ascii():
    """The folding that RFC 5234 does require is unaffected."""
    parser = Literal("Chunked", case_sensitive=False)
    match = next(parser.lparse("cHUNKED", 0))
    assert match.start == 7
    # The matched LiteralNode preserves the source's original spelling.
    assert match.nodes[0].value == "cHUNKED"


def test_x3_ascii_fold_is_length_preserving():
    """A pattern always consumes exactly as many code points as it has,
    so a match no longer depends on what follows it."""
    parser = Literal("ss", case_sensitive=False)
    match = next(parser.lparse("SSx", 0))
    assert match.start == 2
    with pytest.raises(ParseError):
        next(parser.lparse("ßx", 0))


def test_x3_non_ascii_literal_matches_itself():
    """Folding leaves non-ASCII alone rather than rejecting it: a
    non-ASCII literal still matches an exact copy of itself."""
    parser = Literal("Straße", case_sensitive=False)
    match = next(parser.lparse("STRAßE", 0))
    assert match.start == 6
    # ...but the case-mapped spelling of the non-ASCII part does not.
    with pytest.raises(ParseError):
        next(parser.lparse("STRASSE", 0))


def test_x3_grammar_rejects_non_ascii_transfer_coding():
    """The end-to-end shape of the differential: an ASCII grammar must
    not accept a non-ASCII homoglyph of one of its keywords."""
    from abnf.grammars import rfc7230

    assert rfc7230.Rule("transfer-coding").parse_all("chunked")
    for source in ("chun\u212aed", "compre\u017f\u017f"):
        with pytest.raises(ParseError):
            rfc7230.Rule("transfer-coding").parse_all(source)


def test_x3_case_sensitive_does_not_fold():
    """Case-sensitive matching is unchanged: no folding of any kind."""
    parser = Literal("ss", case_sensitive=True)
    with pytest.raises(ParseError):
        next(parser.lparse("SS", 0))
    with pytest.raises(ParseError):
        next(parser.lparse("ß", 0))


# ---------------------------------------------------------------------------
# H5 regression: a left-recursive grammar (`a = a "x" / "x"`) must produce
# a catchable Python exception, not crash the interpreter.  The Python
# backend raises RecursionError; the Rust backend used to recurse through
# native frames with no depth check and SIGSEGV the whole process.
# The test runs in a subprocess so a stack-overflow in pre-fix Rust
# doesn't take down pytest.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# M7 / #187: the Rust bridge registry (Python `Rule` id -> `Arc<NamedRule>`)
# grows as rules are created, and there is no way to reclaim it.  That is
# by design on both sides: `Rule._obj_map` is a permanent symbol table, so
# the Python backend retains every rule too -- about a third of the
# per-rule cost.  A `clear_bridge()` used to exist; it could not free the
# compiled trees (rules embed each other's handles directly) and it broke
# every grammar defined afterwards, so it was removed.  Its absence is
# part of the contract: the bridge keys on the Python object's address,
# which is only sound because `_obj_map` makes those addresses immortal.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND != "rust",
    reason="The bridge registry only exists under the Rust backend.",
)
def test_187_bridge_has_no_clearing_operation():
    import abnf_rust._ext as ext  # type: ignore[import-not-found]

    assert not hasattr(ext, "clear_bridge"), (
        "clear_bridge() breaks every grammar defined after it runs (#187); "
        "it must not come back without also solving Rule._obj_map"
    )


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND != "rust",
    reason="The bridge registry only exists under the Rust backend.",
)
def test_187_bridge_grows_with_rules_created():
    from abnf_rust._ext import bridge_size  # type: ignore[import-not-found]

    before = bridge_size()

    class _BridgeGrowth(Rule):
        pass

    _BridgeGrowth.create('a = "x"')
    assert bridge_size() > before, "expected the bridge to gain an entry"


# ---------------------------------------------------------------------------
# M1 regression: a duck-typed parser (object with `lparse` but no `name`)
# wrapped through Rust's `PyCallbackParser` must propagate non-ParseError
# Python exceptions instead of swallowing them as a generic ParseError.
# The Python reference only catches `ParseError`; everything else
# (TypeError, KeyError, KeyboardInterrupt, ...) propagates uncaught.
# ---------------------------------------------------------------------------


def test_m1_callback_parser_propagates_typeerror():
    class BuggyParser:
        def lparse(self, source, start):
            raise TypeError("simulated bug")

    parser = Concatenation(Literal("a"), BuggyParser())
    with pytest.raises(TypeError, match="simulated bug"):
        list(parser.lparse("ab", 0))


def test_m1_callback_parser_propagates_keyerror():
    class BuggyParser:
        def lparse(self, source, start):
            raise KeyError("missing")

    parser = Concatenation(Literal("a"), BuggyParser())
    with pytest.raises(KeyError):
        list(parser.lparse("ab", 0))


def test_m1_callback_parser_still_treats_parse_error_as_backtrack():
    """Sanity check: a callback that raises `ParseError` must still
    drive normal backtracking, not propagate.  Tested by wrapping it
    in `Alternation(ParseError, "b")` and verifying the "b" branch is
    used."""

    class AlwaysFails:
        def lparse(self, source, start):
            raise ParseError(self, start)

    parser = Alternation(AlwaysFails(), Literal("b"))
    match = next(parser.lparse("b", 0))
    assert match.start == 1


# ---------------------------------------------------------------------------
# `Literal('')` must raise `ParseError` when invoked at a position *past* the
# end of source, and must match everywhere the source reaches, end of input
# included.
#
# The original M2 regression was real: the rust fast path skipped the bounds
# check whenever `plen == 0`, so an empty literal matched at any offset at all.
# The fix made rust mirror the pure-Python guard `start < len(source)` -- but
# that guard was itself wrong, refusing an empty literal at EOF, which is a
# legitimate position rather than an out-of-range one.  So `""` matched at
# every offset except `len(source)`, and `"a" ""` could not match `"a"` while
# `"" "a"` could.
#
# Resolving a backend divergence in favour of the reference, without checking
# the reference against RFC 5234, is what pinned it.  See issue #260.
# ---------------------------------------------------------------------------


def test_260_empty_literal_matches_at_eof_empty_source():
    parser = Literal("")
    assert next(parser.lparse("", 0)).start == 0


def test_260_empty_literal_matches_at_eof_nonempty_source():
    parser = Literal("")
    assert next(parser.lparse("abc", 3)).start == 3


def test_260_empty_literal_matches_inside_source():
    parser = Literal("")
    match = next(parser.lparse("abc", 1))
    assert match.start == 1  # empty literal advances nothing


@pytest.mark.parametrize(("source", "start"), [("", 1), ("abc", 4), ("abc", 99)])
def test_m2_empty_literal_still_raises_past_end_of_source(source: str, start: int):
    """The M2 protection that mattered: an offset beyond the source is out of
    range, and a zero-length pattern must not match there."""
    parser = Literal("")
    with pytest.raises(ParseError):
        next(parser.lparse(source, start))


@pytest.mark.parametrize(("source", "start"), [("a", 0), ("ab", 1), ("", 0)])
def test_260_non_empty_literal_still_needs_room(source: str, start: int):
    parser = Literal("ab")
    with pytest.raises(ParseError):
        next(parser.lparse(source, start))


def test_h5_left_recursive_grammar_is_catchable_not_segfault():
    import subprocess
    import sys

    script = textwrap.dedent(
        """
        from abnf.parser import Rule

        class G(Rule):
            pass

        G.create('a = a "x" / "x"')
        try:
            G('a').parse('xxx', 0)
        except Exception as exc:
            print(f"caught:{type(exc).__name__}")
        else:
            print("no-exception")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Returncode must be 0 (clean exit).  A segfault would yield a
    # negative returncode on POSIX (e.g. -11 for SIGSEGV).
    assert result.returncode == 0, (
        f"left-recursive grammar killed the interpreter: "
        f"returncode={result.returncode}, stderr={result.stderr!r}"
    )
    assert result.stdout.startswith("caught:"), (
        f"expected a caught exception, got: stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )


def test_170_deep_nesting_on_a_small_stack_is_catchable_not_fatal():
    """Regression for issue #170.

    The guard used to bound recursion by counting levels, which only protects
    a stack big enough for the count: 1000 levels wants ~3 MiB, so on a
    smaller stack the process died with no catchable error.  Windows found
    this because it reserves less than Linux and macOS, but the variable that
    matters is stack size, not platform -- `threading.stack_size` reproduces
    it anywhere, which is what this test does so the regression is covered on
    every runner rather than only on Windows.

    Subprocessed because the pre-fix failure mode is a fatal stack overflow,
    which pytest cannot observe in-process.
    """

    import subprocess
    import sys

    script = textwrap.dedent(
        """
        import threading
        from abnf.parser import Rule

        class G(Rule):
            pass

        G.create('nested = "(" [ nested ] ")"')
        src = "(" * 1000 + ")" * 1000
        out = {}

        def run():
            try:
                G("nested").parse_all(src)
            except Exception as exc:
                out["result"] = f"caught:{type(exc).__name__}"
            else:
                out["result"] = "no-exception"

        threading.stack_size(1024 * 1024)
        thread = threading.Thread(target=run)
        thread.start()
        thread.join()
        print(out.get("result", "thread-died"))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"deep nesting on a 1 MiB stack killed the interpreter: "
        f"returncode={result.returncode}, stderr={result.stderr!r}"
    )
    assert result.stdout.startswith("caught:"), (
        f"expected a caught exception, got: stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Public API surface (issue #17).  `Parser` is the protocol the combinators
# satisfy, and it is useful as a type hint in code that accepts or returns a
# parser -- so it belongs at the top level next to the other public names.
# ---------------------------------------------------------------------------


def test_17_parser_is_exported_from_the_top_level():
    import abnf

    assert abnf.Parser is _parser_python.Parser
    assert "Parser" in abnf.__all__


def test_17_public_names_are_all_importable():
    """Everything `__all__` promises must actually be there, whichever
    backend is active."""
    import abnf

    missing = [name for name in abnf.__all__ if not hasattr(abnf, name)]
    assert not missing


def test_17_parser_recognises_combinators_and_user_parsers():
    """It is `runtime_checkable`, and structural -- so a Rust-backed
    combinator satisfies it without inheriting anything."""
    import abnf

    class MyParser:
        def lparse(self, source, start):
            yield Match([], start)

    assert isinstance(Literal("a"), abnf.Parser)
    assert isinstance(Concatenation(Literal("a")), abnf.Parser)
    assert isinstance(Rule("some-rule"), abnf.Parser)
    assert isinstance(MyParser(), abnf.Parser)
    assert not isinstance(object(), abnf.Parser)


# ---------------------------------------------------------------------------
# first_match_alternation (issue #53).  Setting it reached only a rule's
# top-level `Alternation`, so `a = "a" ( "b" / "bc" )` and
# `iuserinfo = *( ... / ... )` could not be configured at all -- the setter
# silently did nothing.  The grammar-wide class attribute did nothing either:
# it shadowed the property, and nothing read it.
#
# Both now work, by recording the alternations as the grammar is built.  That
# is the only approach available to both backends: the Rust combinators expose
# no children, so the tree cannot be walked after the fact.
# ---------------------------------------------------------------------------


class _FirstMatch(Rule):
    first_match_alternation = True


_FirstMatch.create('top = "a" / "ab"')
_FirstMatch.create('nested = *( "a" / "ab" )')
_FirstMatch.create('grouped = "x" ( "b" / "bc" )')


class _LongestMatch(Rule):
    pass


_LongestMatch.create('top = "a" / "ab"')
_LongestMatch.create('nested = *( "a" / "ab" )')
_LongestMatch.create('grouped = "x" ( "b" / "bc" )')
_LongestMatch.create('plain = "b" "c"')
_LongestMatch.create("ref = top")


@pytest.mark.parametrize(
    "rule, source, first, longest",
    [
        ("top", "ab", 1, 2),
        # the cases that could not be configured before
        ("nested", "abab", 1, 4),
        ("grouped", "xbc", 2, 3),
    ],
)
def test_53_class_attribute_reaches_nested_alternations(
    rule: str, source: str, first: int, longest: int
):
    assert _FirstMatch(rule).parse(source, 0)[1] == first
    assert _LongestMatch(rule).parse(source, 0)[1] == longest


def test_53_class_attribute_does_not_shadow_the_property():
    """A bool in the class body used to replace the property outright,
    leaving the grammar's rules unable to read or set the flag."""
    assert _FirstMatch("top").first_match_alternation is True
    assert _LongestMatch("top").first_match_alternation is False


def test_53_per_rule_setter_reaches_nested_alternations():
    rule = _LongestMatch("grouped")
    assert rule.first_match_alternation is False

    rule.first_match_alternation = True
    assert rule.first_match_alternation is True
    assert _LongestMatch("grouped").parse("xbc", 0)[1] == 2

    rule.first_match_alternation = False
    assert rule.first_match_alternation is False
    assert _LongestMatch("grouped").parse("xbc", 0)[1] == 3


def test_53_per_rule_setter_does_not_leak_into_referenced_rules():
    """`ref = top` references a separate rule, which keeps its own
    setting -- otherwise one rule's configuration would mutate another's."""
    _LongestMatch("ref").first_match_alternation = True
    try:
        assert _LongestMatch("top").parse("ab", 0)[1] == 2
    finally:
        _LongestMatch("ref").first_match_alternation = False


def test_53_rule_without_alternation_is_vacuous_not_an_error():
    """`plain = "b" "c"` has nothing to resolve.  The grammar is valid, and
    the same flag set grammar-wide covers plenty of such rules, so setting
    it is simply vacuous -- and the getter says so."""
    rule = _LongestMatch("plain")
    rule.first_match_alternation = True
    assert rule.first_match_alternation is False
    rule.first_match_alternation = False


def test_53_undefined_rule_still_raises():
    class _Undefined(Rule):
        pass

    with pytest.raises(GrammarError):
        _Undefined("nope").first_match_alternation = True


def test_53_incremental_definition_keeps_both_alternations_configurable():
    """`=/` wraps the earlier definition as one arm; alternations from
    both halves must stay reachable."""

    class _Incremental(Rule):
        pass

    _Incremental.create('r = "x" ( "b" / "bc" )')
    _Incremental.create('r =/ "y" ( "c" / "cd" )')

    rule = _Incremental("r")
    rule.first_match_alternation = True
    assert rule.first_match_alternation is True
    assert _Incremental("r").parse("xbc", 0)[1] == 2
    assert _Incremental("r").parse("ycd", 0)[1] == 2


def test_53_hand_built_rule_still_honours_a_top_level_alternation():
    """A rule constructed from a parser object has no recorded
    alternations; the definition itself is the fallback."""

    class _HandBuilt(Rule):
        pass

    _HandBuilt("r", Alternation(Literal("a"), Literal("ab")))
    rule = _HandBuilt("r")
    assert rule.first_match_alternation is False
    rule.first_match_alternation = True
    assert rule.first_match_alternation is True
    assert _HandBuilt("r").parse("ab", 0)[1] == 1


# ---------------------------------------------------------------------------
# Backend capability gate (issue #199).  `abnf` 2.8.1 with `abnf-rust` 2.7.0 --
# a pairing the dependency floor allowed -- died on `import abnf`, because the
# dispatch shim reaches for `set_exclude_hook` (added to the extension in that
# same release) outside the `try/except ImportError` that guards backend
# selection.  `AttributeError` is not an `ImportError`, so the documented
# fallback to pure Python never happened.
#
# `BACKEND_READY` cannot catch this: it is a static flag meaning "this build
# finished", and an older extension sets it too.
# ---------------------------------------------------------------------------


def test_199_shim_declares_everything_it_binds():
    """The required-attribute list must not drift from what the module
    actually pulls off the backend."""
    source = pathlib.Path(_parser.__file__).read_text(encoding="utf-8")
    bound = set(re.findall(r"_backend\.(\w+)", source))
    declared = set(_parser._REQUIRED_BACKEND_ATTRS)
    assert bound <= declared, f"bound but not declared: {sorted(bound - declared)}"


@pytest.mark.skipif(_parser._BACKEND != "rust", reason="Needs the extension to probe.")
def test_199_active_backend_satisfies_the_requirements():
    assert _parser._missing_backend_attrs(_parser._backend) == []


def test_199_missing_attribute_is_detected():
    class _Stub:
        pass

    stub = _Stub()
    for name in _parser._REQUIRED_BACKEND_ATTRS:
        if name != "set_exclude_hook":
            setattr(stub, name, object())
    assert _parser._missing_backend_attrs(stub) == ["set_exclude_hook"]


@pytest.mark.skipif(
    _parser._BACKEND != "rust", reason="Needs the extension to build a stub from."
)
def test_199_too_old_extension_falls_back_instead_of_crashing():
    """End to end, in a subprocess: an extension missing a required name
    must leave `import abnf` working, on the pure-Python backend, with a
    warning that names what is missing."""
    program = textwrap.dedent(
        """
        import sys, types, warnings, json
        import abnf_rust as real

        # Stand in for an older build: BACKEND_READY is True, but the
        # name added in the importing version's release is absent.
        stub = types.ModuleType("abnf_rust")
        for name in dir(real):
            if not name.startswith("_") and name != "set_exclude_hook":
                setattr(stub, name, getattr(real, name))
        sys.modules["abnf_rust"] = stub

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            import abnf
            import abnf.parser as parser
            messages = [str(w.message) for w in caught
                        if issubclass(w.category, RuntimeWarning)]

        from abnf.parser import Rule

        class G(Rule):
            pass

        G.create("s = 1*%x61-7A")
        print(json.dumps({
            "backend": parser._BACKEND,
            "messages": messages,
            "parsed": G("s").parse_all("abc").value,
        }))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["backend"] == "python"
    assert payload["parsed"] == "abc"
    assert any("set_exclude_hook" in m for m in payload["messages"])
    assert any("too old" in m for m in payload["messages"])


# ---------------------------------------------------------------------------
# Undefined rule references (issue #201).  A rule that was never defined is a
# broken grammar, not input that failed to match.  The Rust engine returned an
# ordinary ParseError, which is indistinguishable from "this alternative did
# not match" -- so an enclosing Alternation or Repetition swallowed it as
# backtracking and a typo'd rule name silently deleted that branch.
#
# The same defect was fixed for exclusions in 2.8.1; the plain definition
# lookup one screen below it in rule.rs was missed.
# ---------------------------------------------------------------------------


def test_201_undefined_rule_in_an_alternation_raises():
    """The reported case: the branch must not be silently dropped."""

    class UndefinedInAlternation(Rule):
        pass

    UndefinedInAlternation.create('a = b / "x"')  # `b` is never defined

    # Input that the *other* alternative matches must still raise: the
    # grammar is broken regardless of which branch would have won.
    with pytest.raises(GrammarError, match="Undefined rule"):
        UndefinedInAlternation("a").parse_all("x")

    with pytest.raises(GrammarError, match="Undefined rule"):
        UndefinedInAlternation("a").parse_all("zz")


def test_201_undefined_rule_in_a_repetition_raises():
    class UndefinedInRepetition(Rule):
        pass

    UndefinedInRepetition.create("a = *b")

    with pytest.raises(GrammarError, match="Undefined rule"):
        UndefinedInRepetition("a").parse_all("")


def test_201_undefined_rule_referenced_directly_raises():
    class UndefinedDirect(Rule):
        pass

    UndefinedDirect.create("a = b")

    with pytest.raises(GrammarError, match="Undefined rule"):
        UndefinedDirect("a").parse_all("x")


def test_201_forward_reference_still_works_once_defined():
    """The check must fire on a missing definition, not on definition
    order: a rule may be referenced before it is defined."""

    class ForwardReference(Rule):
        pass

    ForwardReference.create('a = b / "x"')
    ForwardReference.create('b = "y"')

    assert ForwardReference("a").parse_all("y").value == "y"
    assert ForwardReference("a").parse_all("x").value == "x"


# ---------------------------------------------------------------------------
# Re-entrant parses over a different source (issue #202).  Memoisation is
# scoped by epoch, and cache entries are keyed by position alone, so an epoch
# may only ever see one source.  Nested FFI entries shared the enclosing
# parse's epoch on the reasoning that a callback re-entering the engine is
# part of the same parse -- but the `Parser` protocol is public, and a custom
# parser may parse anything it likes while it runs.  Entries made against the
# inner source then answered lookups against the outer one.
#
# The pure-Python backend was never affected: its memo carries the source and
# checks identity (`ctx[0] is source`) before use.
# ---------------------------------------------------------------------------


def test_202_re_entrant_parse_on_a_different_source():
    """The reported case: parsing other text mid-parse must not change
    what the enclosing parse matches."""
    inner = Repetition(Repeat(0, None), Literal("a"))

    class ReEnter:
        def lparse(self, source, start):
            list(inner.lparse("bbbb", 0))  # a different source, mid-parse
            yield Match([], start)  # then match zero width

    outer = Concatenation(cast(Parser, ReEnter()), inner)
    assert max(m.start for m in outer.lparse("aaa", 0)) == 3


def test_202_re_entrant_parse_on_the_same_source_is_unaffected():
    """Same-source re-entry keeps sharing the epoch -- an epoch change
    resets the caches it touches, so claiming one unconditionally would
    wipe the enclosing parse's memo on every callback."""

    class Ambiguous(Rule):
        pass

    Ambiguous.create('amb = 1*("a" / "aa")')
    inner = Ambiguous("amb")

    class SameSource:
        def lparse(self, source, start):
            inner.parse(source, 0)  # the same source object
            yield Match([], start)

    class Outer(Rule):
        pass

    Outer(
        "loop",
        Repetition(
            Repeat(1, None),
            Concatenation(cast(Parser, SameSource()), Ambiguous("amb")),
        ),
    )
    source = "a" * 12
    assert Outer("loop").parse(source, 0)[1] == len(source)


def test_202_nested_different_sources_restore_the_outer_scope():
    """Two levels of re-entry, each on its own text: unwinding must put
    the enclosing parse back on its own entries."""
    inner = Repetition(Repeat(0, None), Literal("a"))

    class Deep:
        def lparse(self, source, start):
            list(inner.lparse("bb", 0))
            list(inner.lparse("cccc", 0))
            yield Match([], start)

    outer = Concatenation(cast(Parser, Deep()), inner)
    assert max(m.start for m in outer.lparse("aaaa", 0)) == 4


# ---------------------------------------------------------------------------
# Parser identification (issue #203).  The Rust layer decided that anything
# with `name` and `lparse` was a Rule, and registered it in the bridge -- a
# registry keyed by the Python object's *address*.  Two defects followed:
# such an object became a definition-less `NamedRule` whose own `lparse` was
# never called, and the registry's soundness argument (rules are immortal,
# via `Rule._obj_map`) does not hold for an arbitrary user object, so a freed
# one's address could be handed to a new `Rule` that inherited its handle.
#
# Rules are now identified by type.  Everything else with `lparse` goes to the
# callback path, which holds a reference to the object -- so it cannot dangle.
# ---------------------------------------------------------------------------


def test_203_duck_typed_parser_with_a_name_attribute_is_called():
    """`name` is an ordinary attribute; it must not change dispatch."""

    class NamedDuck:
        name = "descriptive"

        def lparse(self, source, start):
            if start < len(source):
                yield Match(
                    [cast(Node, LiteralNode(source[start], start, 1))], start + 1
                )
            else:
                raise ParseError(self, start)

    parser = Concatenation(Literal("x"), cast(Parser, NamedDuck()))
    match = next(iter(parser.lparse("xz", 0)))
    assert match.nodes[-1].value == "z"


def test_203_a_parser_tree_keeps_its_python_parsers_alive():
    """The property that makes the address-reuse hazard impossible: an
    embedded parser is owned by the tree, so its address cannot be
    recycled while the tree still refers to it."""

    class Duck:
        name = "duck"

        def lparse(self, source, start):
            yield Match([cast(Node, LiteralNode(source[start], start, 1))], start + 1)

    duck = Duck()
    ref = weakref.ref(duck)
    tree = Concatenation(Literal("x"), cast(Parser, duck))
    del duck
    gc.collect()
    assert ref() is not None, "the tree does not own the parser it was built from"

    del tree
    gc.collect()
    assert ref() is None, "the parser outlived every tree referring to it"


@pytest.mark.skipif(
    _parser._BACKEND != "rust", reason="The bridge only exists under Rust."
)
def test_203_real_rules_still_take_the_bridge_fast_path():
    """Identifying rules by type must not cost the optimisation the
    attribute check existed for."""
    from abnf_rust._ext import bridge_size  # type: ignore[import-not-found]

    class BridgeFastPath(Rule):
        pass

    BridgeFastPath.create('inner = "a"')
    before = bridge_size()
    BridgeFastPath("outer", Concatenation(Literal("x"), BridgeFastPath("inner")))
    assert bridge_size() > before


# ---------------------------------------------------------------------------
# Backend API parity (issue #204).  Four small divergences, grouped because
# they share a cause: the Rust pyclasses reimplement parts of the Python API
# surface and drifted from it.  The pure-Python implementation is the
# reference in each case.
# ---------------------------------------------------------------------------


def test_204_repeat_bound_beyond_usize_is_not_an_error():
    """Python's ints are unbounded, so this is odd but valid ABNF that
    the reference backend parses happily -- the bound is never reached.
    Raising `OverflowError` also escaped the documented exception
    contract, being neither `GrammarError` nor `ParseError`."""

    class HugeBound(Rule):
        pass

    HugeBound.create('a = 2*99999999999999999999"x"')
    assert HugeBound("a").parse_all("xxx").value == "xxx"


@pytest.mark.parametrize(
    "args, expected",
    [
        ((3, 2), GrammarError),  # impossible range
        ((0, -1), GrammarError),  # negative max is < min
        ((0, "x"), TypeError),  # not a number at all
    ],
)
def test_204_repeat_still_rejects_what_it_should(args, expected):
    """Saturating a huge bound must not swallow the genuine errors."""
    with pytest.raises(expected):
        Repeat(*args)


def test_204_range_literal_case_sensitivity_reads_the_same():
    """A range compares by code point either way, so the attribute is
    inert -- but it should read alike on both backends."""
    assert Literal(("a", "z")).case_sensitive is False
    assert Literal("a").case_sensitive is False
    assert Literal("a", case_sensitive=True).case_sensitive is True


def test_204_node_equality_is_structural():
    """Comparing concatenated values called two different parse trees
    equal whenever they spanned the same text."""

    class Flat(Rule):
        pass

    class Nested(Rule):
        pass

    Flat.create('a = "xy" / ("x" "y")')
    Nested.create('a = ("x" "y") / "xy"')

    flat = Flat("a").parse_all("xy")
    nested = Nested("a").parse_all("xy")
    assert flat.value == nested.value == "xy"
    assert len(flat.children) != len(nested.children)
    assert flat != nested


def test_204_node_equality_compares_children_recursively():
    same = Node("r", cast(Node, Node("c", cast(Node, LiteralNode("a", 0, 1)))))
    other = Node("r", cast(Node, Node("c", cast(Node, LiteralNode("b", 0, 1)))))
    assert same == Node("r", cast(Node, Node("c", cast(Node, LiteralNode("a", 0, 1)))))
    assert same != other
    # ...and a node is never equal to something that is not one.
    assert same != LiteralNode("a", 0, 1)
    assert same != "r"


def test_204_parse_tree_nodes_are_unhashable():
    """`__eq__` without `__hash__` makes a class unhashable in Python,
    and the reference `LiteralNode` does exactly that.  `Node` is
    unhashable too, so no parse-tree node is hashable on either
    backend."""
    with pytest.raises(TypeError):
        hash(LiteralNode("a", 0, 1))
    with pytest.raises(TypeError):
        hash(Node("x"))


# ---------------------------------------------------------------------------
# Offsets from a custom parser (issue #218).  A rule's definition may be a
# Python parser, and the end offset it reports is not validated -- it can be
# past the end of the source, or before where the match began.  The exclusion
# check sliced the source with it, so a bad offset panicked, and a panic
# crosses the FFI as `PanicException`: a `BaseException`, which `except
# ParseError` -- or even `except Exception` -- does not catch.
#
# Text that is not in the source cannot be text the excluded rule matches, so
# a nonsensical span means "not excluded"; the offset then fails naturally
# further up, as it does on the pure-Python backend.
# ---------------------------------------------------------------------------


class _OffsetPast:
    """Reports a match ending far beyond the source."""

    def lparse(self, source, start):
        yield Match([cast(Node, LiteralNode("a", start, 1))], 1000)


class _OffsetBefore:
    """Reports a match ending before it began."""

    def lparse(self, source, start):
        yield Match([cast(Node, LiteralNode("a", start, 1))], 0)


@pytest.mark.parametrize("parser_cls", [_OffsetPast, _OffsetBefore])
def test_218_bad_offset_under_an_exclusion_raises_parse_error(parser_cls):
    class BadOffset(Rule):
        pass

    BadOffset.create('kw = "zzz"')
    BadOffset("bad", cast(Parser, parser_cls()))
    BadOffset("bad").exclude_rule(BadOffset("kw"))

    # The contract is that parsing raises ParseError -- not that it raises
    # something.  `PanicException` derives from BaseException, so a bare
    # `except ParseError` would not have caught the old behaviour.
    with pytest.raises(ParseError):
        Concatenation(BadOffset("bad"), Literal("b")).lparse("ab", 0)
        next(iter(Concatenation(BadOffset("bad"), Literal("b")).lparse("ab", 0)))


def test_218_bad_offset_without_an_exclusion_is_unchanged():
    """Only the exclusion path sliced unchecked; this shape always
    degraded gracefully and must continue to."""

    class NoExclusion(Rule):
        pass

    NoExclusion("bad", cast(Parser, _OffsetPast()))
    with pytest.raises(ParseError):
        next(iter(Concatenation(NoExclusion("bad"), Literal("b")).lparse("ab", 0)))


def test_218_a_valid_exclusion_still_excludes():
    """The guard must not turn every exclusion into a no-op."""

    class StillExcludes(Rule):
        pass

    StillExcludes.create("word = 1*%x61-7A")
    StillExcludes.create('kw = "stop"')
    StillExcludes("word").exclude_rule(StillExcludes("kw"))

    assert StillExcludes("word").parse_all("go").value == "go"
    with pytest.raises(ParseError):
        StillExcludes("word").parse_all("stop")


# ---------------------------------------------------------------------------
# ParseError attributes (issue #219).  `start` means the same thing on both
# backends.  `parser` does not: pure Python stores the parser object, the Rust
# engine a description string prepared once at construction, because an error
# is built on every failed alternative.  Documented rather than reconciled --
# carrying the object would put an allocation back on the backtracking path
# for an attribute only diagnostics read.
# ---------------------------------------------------------------------------


def test_219_parse_error_start_is_the_documented_contract():
    from abnf.grammars import rfc3986

    with pytest.raises(ParseError) as excinfo:
        rfc3986.Rule("URI").parse_all("not a uri")
    assert excinfo.value.start == 0
    # `str()` works on both backends, whatever `parser` holds.
    assert str(excinfo.value).endswith(": 0")


def test_219_parse_error_parser_is_documented_as_backend_dependent():
    """Pin the documentation, not the type: the docstring must keep
    warning that reaching into `parser` is not portable."""
    doc = ParseError.__doc__ or ""
    assert "description string" in doc
    assert "start" in doc


# Values returned by a custom parser (issue #220).  Engine-built terminals are
# spans of the source, which is what lets their values be produced by slicing
# it (#173).  A node handed *in* by a custom parser need not correspond to any
# span: returning a normalised or synthesised value is a legitimate thing to
# write, and the pure-Python backend keeps it.  Slicing the source for one of
# those silently replaced it with unrelated text.
# ---------------------------------------------------------------------------


class _Synth:
    """Returns a value that is not the text it spans."""

    def lparse(self, source, start):
        yield Match([cast(Node, LiteralNode("SYNTH", 0, 2))], 2)


def test_220_a_returned_value_is_preserved():
    match = next(iter(Concatenation(cast(Parser, _Synth())).lparse("abc", 0)))
    assert match.nodes[0].value == "SYNTH"


def test_220_an_enclosing_node_includes_the_returned_value():
    """The enclosing value cannot be one slice of the source any more,
    so it has to be joined from the parts."""

    class Wrapper(Rule):
        pass

    Wrapper("wrap", Concatenation(cast(Parser, _Synth()), Literal("c")))
    assert Wrapper("wrap").parse_all("abc").value == "SYNTHc"


def test_220_a_returned_value_may_contain_a_surrogate():
    """The value crosses the boundary as code points, so it is subject
    to the same domain as the source (#173)."""

    class Surrogate:
        def lparse(self, source, start):
            yield Match([cast(Node, LiteralNode("\ud800x", 0, 2))], 2)

    match = next(iter(Concatenation(cast(Parser, Surrogate())).lparse("abc", 0)))
    assert match.nodes[0].value == "\ud800x"


def test_220_engine_built_values_are_unchanged():
    """The slicing fast path still applies to everything the engine
    builds itself, which is all of a normal parse."""

    class Ordinary(Rule):
        pass

    Ordinary.create("s = 1*%x61-7A")
    node = Ordinary("s").parse_all("abc")
    assert node.value == "abc"
    assert [c.value for c in node.children] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Backend surface parity (issue #221).  The Rust pyclasses are a different kind
# of object from the pure-Python classes, and two of the differences showed
# through: the classes were final, and `Repeat` rejected values the reference
# accepts.
# ---------------------------------------------------------------------------


def test_221_parse_tree_classes_can_be_subclassed():
    """The how-to says installing the extension changes nothing in your
    code; subclassing a node is a plausible thing to have written."""

    class MyNode(Node):
        pass

    class MyLiteralNode(LiteralNode):
        pass

    class MyMatch(Match):
        pass

    assert issubclass(MyNode, Node)
    assert issubclass(MyLiteralNode, LiteralNode)
    assert issubclass(MyMatch, Match)


@pytest.mark.parametrize(
    "args",
    [
        (-1,),  # pure Python builds it; Repetition then behaves as min=0
        (0, 2.5),  # a float max never equals the count, so unbounded
        (0, 3.0),  # ...but an integral one caps where the integer would
        (),  # the default
        (1, 5),
    ],
)
def test_221_repeat_accepts_what_the_reference_accepts(args):
    """Parse behaviour is what has to agree.  The stored attributes may
    differ for absurd inputs -- a negative min reads back as 0 -- but no
    input reaches either bound, so nothing observable follows from it."""
    repetition = Repetition(Repeat(*args), Literal("a"))
    ends = sorted({m.start for m in repetition.lparse("aaa", 0)})
    assert ends  # constructed, and parses


@pytest.mark.parametrize(
    "args, expected",
    [
        ((3, 2), GrammarError),  # impossible range
        ((0, -1), GrammarError),  # negative max is < min
        ((0, "x"), TypeError),  # not a number at all
    ],
)
def test_221_repeat_still_rejects_what_it_should(args, expected):
    """Relaxing the accepted set must not swallow the genuine errors --
    a negative *max* converts to a float cleanly, so it needs the check
    that a float bound does not route around the `max < min` test."""
    with pytest.raises(expected):
        Repeat(*args)


def test_221_mutating_a_parse_tree_container_is_documented_not_supported():
    """Neither backend errors, and they do different things -- pure
    Python mutates, Rust rebuilds the container per access so the change
    is dropped.  Making the Rust getters return tuples would raise, but
    a tuple stops comparing equal to a list, which breaks reading code
    to fix writing code that should not exist.  So the API reference
    records it, and this pins that the note stays put."""
    reference = pathlib.Path("docs/reference/api.md").read_text(encoding="utf-8")
    assert "Parse trees are results, not workspaces" in reference
    assert "silently does nothing" in reference

    # Whatever the backend does, reading the tree is unaffected.
    node = Node("x", cast(Node, LiteralNode("a", 0, 1)))
    assert len(node.children) == 1
    assert node.children[0].value == "a"


# Issue #259: `visit` looks the node name up casefolded, but the dispatch
# table was keyed on the method-name suffix verbatim -- so `visit_URI`, the
# spelling the rule's own name suggests, was filed under a key nothing asks
# for.  The miss returns `_skip_visit`, so the node was silently skipped with
# no error and no warning.
@pytest.mark.parametrize(
    ('rule_module', 'rule_name', 'src', 'method'),
    [
        ('rfc3986', 'URI', 'http://example.com/', 'visit_URI'),
        ('rfc3986', 'URI', 'http://example.com/', 'visit_uri'),
        ('rfc3986', 'IPv4address', '1.2.3.4', 'visit_IPv4address'),
        ('rfc9051', 'ATOM-CHAR', 'a', 'visit_ATOM_CHAR'),
        ('rfc9051', 'ATOM-CHAR', 'a', 'visit_atom_char'),
    ],
)
def test_259_visitor_dispatch_is_case_insensitive(
    rule_module: str, rule_name: str, src: str, method: str
):
    from importlib import import_module

    module = import_module(f'abnf.grammars.{rule_module}')
    node = module.Rule(rule_name).parse_all(src)

    called = []
    visitor = NodeVisitor()
    setattr(visitor, method, lambda n: called.append(n.name))
    # Re-run __init__ so the instance-attribute scan sees the method we just
    # attached, as it would for one defined on a subclass.
    NodeVisitor.__init__(visitor)
    visitor.visit(node)
    assert called == [rule_name], f'{method} was not called for node {rule_name!r}'


def test_259_lowercase_spelling_still_wins_when_both_are_defined():
    """Rule names are case-insensitive, so both spellings name one rule.
    Whichever won before must keep winning."""
    from abnf.grammars import rfc3986

    class V(NodeVisitor):
        def visit_URI(self, node):
            return 'upper'

        def visit_uri(self, node):
            return 'lower'

    node = rfc3986.Rule('URI').parse_all('http://example.com/')
    assert V().visit(node) == 'lower'


def test_259_an_unrelated_node_is_still_skipped():
    """The fix must not make dispatch match more than the node's own name."""
    from abnf.grammars import rfc3986

    class V(NodeVisitor):
        def visit_scheme(self, node):
            return 'scheme'

    node = rfc3986.Rule('URI').parse_all('http://example.com/')
    assert V().visit(node) is None
# Issue #258: `first_match_alternation` is a descriptor serving both supported
# spellings.  Assigning it on a class object -- rather than in a class body --
# was an ordinary type.__setattr__ that dropped a bool into the class dict and
# shadowed it.  Nothing read that bool, so the attribute reported a setting the
# parser was not using; and the documented per-rule spelling silently stopped
# working for that class from then on, because it too went to a plain dict.
def test_258_assigning_on_the_class_object_is_refused():
    class M(Rule):
        pass

    M.create('r = "a" / "ab"')
    with pytest.raises(AttributeError, match='cannot be assigned'):
        M.first_match_alternation = True


def test_258_the_message_names_both_supported_spellings():
    class M(Rule):
        pass

    with pytest.raises(AttributeError) as excinfo:
        M.first_match_alternation = True
    message = str(excinfo.value)
    assert 'class body' in message
    assert "first_match_alternation = True" in message


def test_258_class_body_spelling_still_works():
    class N(Rule):
        first_match_alternation = True

    N.create('r = "a" / "ab"')
    # First match takes "a" and stops; longest match would consume "ab".
    assert N('r').parse('ab', 0)[1] == 1


def test_258_per_rule_spelling_still_works():
    class P(Rule):
        pass

    P.create('r = "a" / "ab"')
    assert P('r').parse('ab', 0)[1] == 2
    P('r').first_match_alternation = True
    assert P('r').parse('ab', 0)[1] == 1
    P('r').first_match_alternation = False
    assert P('r').parse('ab', 0)[1] == 2


def test_258_a_non_bool_in_the_class_body_is_refused():
    """It shadows the descriptor exactly as a stray assignment does."""
    with pytest.raises(TypeError, match='must be True or False'):

        class Q(Rule):
            first_match_alternation = 1  # pyright: ignore[reportAssignmentType]


def test_258_other_class_attributes_are_unaffected():
    class R2(Rule):
        pass

    R2.grammar = ['r = "a"']
    assert R2.grammar == ['r = "a"']
    R2.create('r = "a"')
    assert R2('r').parse_all('a').value == 'a'


# Issue #261: two grammar-level mistakes escaped as raw Python exceptions.
@pytest.mark.parametrize(
    'grammar',
    ['r = %x110000', 'r = %x7FFFFFFF', 'r = %d1114112', 'r = %b1000000000000000000000'],
)
def test_261_num_val_beyond_the_code_point_space(grammar: str):
    """`chr` raised ValueError, naming neither the rule nor the grammar."""

    class R(Rule):
        pass

    with pytest.raises(GrammarError, match='not a Unicode code point'):
        R.create(grammar)


@pytest.mark.parametrize('grammar', ['r = %x10FFFF', 'r = %x41', 'r = %d1114111'])
def test_261_the_top_of_the_range_is_still_valid(grammar: str):
    class R(Rule):
        pass

    R.create(grammar)
    assert R('r').definition is not None


def test_261_incremental_alternative_needs_an_existing_definition():
    """RFC 5234 section 3.3.  Was a bare AttributeError."""

    class R(Rule):
        pass

    with pytest.raises(GrammarError, match="no definition to add to"):
        R.create('nope =/ "a"')


def test_261_incremental_alternative_still_works_when_defined():
    class R(Rule):
        pass

    R.create('q = "x"')
    R.create('q =/ "y"')
    assert R('q').parse_all('x').value == 'x'
    assert R('q').parse_all('y').value == 'y'


# Issue #262: the per-parse memo keyed on `id(self)`, and an id is unique only
# among live objects -- a Repetition freed mid-parse could have its address
# reused and hand its cached matches to a different parser.
def test_262_memo_keys_on_the_object_not_its_address():
    import pathlib

    import abnf._parser_python as reference

    # Read the file rather than inspect the class: `abnf.parser` patches
    # backend classes onto this module, so under the rust backend
    # `reference.Repetition` is not the pure-Python one.
    source = pathlib.Path(reference.__file__).read_text(encoding='utf-8')
    assert 'cache_key = (self, start)' in source
    assert 'cache_key = (id(self), start)' not in source


def test_262_repetition_results_are_still_correct_and_cached():
    class R(Rule):
        pass

    R.create('r = 1*"ab"')
    assert R('r').parse_all('ababab').value == 'ababab'
    # Same rule, different sources: nothing may carry over between parses.
    assert R('r').parse_all('ab').value == 'ab'
    with pytest.raises(ParseError):
        R('r').parse_all('abx')
