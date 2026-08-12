import pathlib
import textwrap
from typing import cast

import pytest

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
    NumValVisitor,
    Option,
    ParseCache,
    ParseError,
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

    ParseCache.clear_caches()
    for c in ParseCache.list():
        assert len(c) == 0
        assert c.misses == 0
        assert c.hits == 0


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
# Surrogate code points (issue #173).  Rust `str` is well-formed UTF-8 and so
# cannot hold one; Python `str` can.  The behaviour gap is not fixed here --
# these tests pin the *diagnosis*, which used to be a TypeError claiming a
# string was not a string, and a bare codec traceback that never mentioned
# abnf.  They also record the parity gap itself, so closing #173 will fail
# them and prompt an update.
# ---------------------------------------------------------------------------

_BACKEND_IS_RUST = __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND == "rust"
_SURROGATE_SOURCE = b"caf\xe9".decode("utf-8", "surrogateescape")


@pytest.mark.skipif(not _BACKEND_IS_RUST, reason="Rust backend only.")
def test_173_surrogate_grammar_names_the_real_problem():
    class SurrogateGrammar(Rule):
        pass

    with pytest.raises(GrammarError) as excinfo:
        SurrogateGrammar.create("s = %xD800-DBFF")
    message = str(excinfo.value)
    assert "surrogate" in message
    assert "ABNF_NO_RUST" in message


@pytest.mark.skipif(not _BACKEND_IS_RUST, reason="Rust backend only.")
def test_173_surrogate_input_names_the_real_problem():
    class SurrogateInputGrammar(Rule):
        pass

    SurrogateInputGrammar.create("s = 1*%x00-10FFFF")
    with pytest.raises(ValueError) as excinfo:
        SurrogateInputGrammar("s").parse_all(_SURROGATE_SOURCE)
    message = str(excinfo.value)
    assert "surrogate" in message
    assert "ABNF_NO_RUST" in message


@pytest.mark.skipif(_BACKEND_IS_RUST, reason="Pure-Python backend only.")
def test_173_pure_python_handles_surrogates():
    # The workaround the messages above point at has to actually work.
    class SurrogatePythonGrammar(Rule):
        pass

    SurrogatePythonGrammar.create("s = 1*%x00-10FFFF")
    assert SurrogatePythonGrammar("s").parse_all(_SURROGATE_SOURCE).value == _SURROGATE_SOURCE


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
# H3 regression: case-insensitive Literal must honour Unicode casefold
# expansion.  Python's `str.casefold()` maps some non-ASCII characters to
# multi-character ASCII sequences (most famously 'ß' → 'ss', 'ﬃ' → 'ffi').
# Per the pure-Python reference, `Literal('ss', case_sensitive=False)`
# matches a source consisting of 'ß'.  The Rust backend's ASCII fast path
# missed this case (byte-level compare against pattern 'ss' against source
# bytes 0xc3 0x9f fails) and silently raised `ParseError`.
# ---------------------------------------------------------------------------


def test_h3_casefold_expansion_ss_matches_eszett():
    """'ß'.casefold() == 'ss' — Literal('ss') should match 'ß' under
    case-insensitive comparison."""
    parser = Literal("ss", case_sensitive=False)
    match = next(parser.lparse("ß", 0))
    assert match.start == 1  # consumed one code point of source
    # The matched LiteralNode preserves the source's original spelling.
    assert match.nodes[0].value == "ß"


def test_h3_casefold_expansion_ffi_ligature():
    """'ﬃ'.casefold() == 'ffi'."""
    parser = Literal("ffi", case_sensitive=False)
    match = next(parser.lparse("ﬃ", 0))
    assert match.start == 1
    assert match.nodes[0].value == "ﬃ"


def test_h3_casefold_expansion_uppercase_ss_matches_eszett():
    """'SS'.casefold() == 'ss' and 'ß'.casefold() == 'ss'."""
    parser = Literal("SS", case_sensitive=False)
    match = next(parser.lparse("ß", 0))
    assert match.start == 1


def test_h3_case_sensitive_does_not_expand():
    """In case-sensitive mode, 'ß' should NOT match 'ss' — casefold
    expansion is disabled by definition."""
    parser = Literal("ss", case_sensitive=True)
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
# M7 regression: the Rust bridge registry (Python `Rule` id →
# `Arc<NamedRule>`) grows monotonically as new rules are created.  For
# long-lived processes that load grammars dynamically, that's a memory
# leak — Python's class-level `_obj_map` already keeps every Rule
# alive, but the Rust shadow adds a second `Arc` to the parser tree.
# `clear_bridge()` lets callers drop the shadow state when they know
# they're done with a batch of dynamic grammars; subsequent parses
# repopulate the bridge lazily.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("abnf.parser", fromlist=["_BACKEND"])._BACKEND != "rust",
    reason="The bridge registry only exists under the Rust backend.",
)
def test_m7_clear_bridge_releases_entries():
    from abnf_rust._ext import bridge_size, clear_bridge  # type: ignore[import-not-found]

    # Start from a known state.
    clear_bridge()
    assert bridge_size() == 0

    # Define a grammar; rule construction populates the bridge as
    # `_set_definition_hook` fires.
    class _M7Grammar(Rule):
        pass

    _M7Grammar.create('a = "x"')
    populated = bridge_size()
    assert populated > 0, "expected the bridge to gain at least one entry"

    # The headline fix: clear_bridge drops everything.
    clear_bridge()
    assert bridge_size() == 0


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
# M2 regression: `Literal('')` must raise `ParseError` when invoked at a
# position past the end of source.  The pure-Python reference checks
# `start < len(source)` before considering any match (so even an empty
# literal cannot match at EOF); the Rust fast path skipped that check
# whenever `plen == 0`, silently matching the empty string at EOF.
# ---------------------------------------------------------------------------


def test_m2_empty_literal_raises_at_eof_empty_source():
    parser = Literal("")
    with pytest.raises(ParseError):
        next(parser.lparse("", 0))


def test_m2_empty_literal_raises_at_eof_nonempty_source():
    parser = Literal("")
    with pytest.raises(ParseError):
        next(parser.lparse("abc", 3))


def test_m2_empty_literal_matches_inside_source():
    """Sanity check: empty literal does match when start is strictly
    inside the source (Python's `start < len(source)` is true)."""
    parser = Literal("")
    match = next(parser.lparse("abc", 1))
    assert match.start == 1  # empty literal advances nothing


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
