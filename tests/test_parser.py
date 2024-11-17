import pathlib
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


def test_repetition_cached_oarseerror():
    src = "a"
    parser = Repetition(Repeat(1, 1), Literal("*"))
    parser.lparse_cache[(src, 0)] = ParseError(parser, 0)
    with pytest.raises(ParseError) as exc_info:
        next(parser.lparse(src, 0))
    assert exc_info.value is parser.lparse_cache[(src, 0)]


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
