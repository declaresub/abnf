import pytest
from abnf.parser import (Node, LiteralNode, Literal, ABNFGrammarRule, 
ABNFGrammarRuleNodeVisitor, Rule, ParseError, Alternation, NumValVisitor,
    Concatenation, Repeat, Repetition, Option, GrammarError, flatten)


def test_empty_literal():
    parser = Literal('')
    assert parser

def test_literal():
    parser = Literal('moof')
    source = 'moof'
    node, start = parser.parse(source, 0)
    assert node.value == 'moof'

@pytest.mark.parametrize("value", [None, 47, ('a', 'b', 'c'), (1, 2)])
def test_literal_bad_value(value):
    with pytest.raises(TypeError):
        Literal(value)

def test_literal_range_fail():
    parser = Literal(('a', 'b'))
    with pytest.raises(ParseError):
        parser.parse('c', 0)

def test_literal_range_out_of_bounds():
    parser = Literal(('a', 'b'))
    with pytest.raises(ParseError):
        parser.parse('a', 1)

def test_empty_literal_out_of_bounds():
    parser = Literal('')
    src = 'a'
    with pytest.raises(ParseError):
        parser.parse(src, 1)

@pytest.mark.parametrize('value, expected', [('foo', r"Literal('foo')"), ('\r', r"Literal('\x0d')")])
def test_literal_str(value, expected):
    parser = Literal(value)
    assert str(parser) == expected

@pytest.mark.parametrize('value, src', [('A', 'A'), ('A', 'a'), ('a', 'A'), ('a', 'a')])
def test_literal_case_insensitive(value, src):
    parser = Literal(value)
    node, start = parser.parse(src, 0)
    assert node.value == src

@pytest.mark.parametrize("src", ['moof', 'MOOF', 'mOOf', 'mOoF'])
def test_char_val(src):
    node, start = ABNFGrammarRule('char-val').parse('"moof"', 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_char_val(node)
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value == src

@pytest.mark.parametrize("src", ['moof', 'MOOF', 'mOOf', 'mOoF'])
def test_char_val_case_insensitive(src):
    node, start = ABNFGrammarRule('char-val').parse('%i"moof"', 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_char_val(node)
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value.casefold() == 'moof'

def test_CharVal_case_sensitive():
    node, start = ABNFGrammarRule('char-val').parse('%s"MOOF"', 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_char_val(node)
    assert parser.case_sensitive

def test_char_val_case_sensitive():
    node, start = ABNFGrammarRule('char-val').parse('%s"MOOF"', 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_char_val(node)
    src = 'MOOF'
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value == src

@pytest.mark.parametrize("src", ['MOOF', 'mOOf', 'mOoF'])
def test_char_val_case_sensitive_fail(src):
    node, start = ABNFGrammarRule('char-val').parse('%s"moof"', 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_char_val(node)
    with pytest.raises(ParseError):
        parser.parse(src, 0)

def test_bin_val():
    src = "b01111000"
    node = ABNFGrammarRule('bin-val').parse_all(src)
    visitor = NumValVisitor()
    visitor.visit(node)
    assert visitor.value == 'x'

@pytest.mark.parametrize("src", ['A', 'B', 'Z'])
def test_literal_range(src):
    parser = Literal(('\x41', '\x5A'))
    node, start = parser.parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['foo', 'bar'])
def test_alternation(src):
    parser = Alternation(Literal('foo'), Literal('bar'))
    node, start = parser.parse(src, 0)
    assert node.value == src

# test repetition and match of empty elements.
@pytest.mark.parametrize("src, expected", [
    ('1*43', (1, 43)),
    ('1*', (1, None)),
    ('*43', (0, 43)),
    ('43', (43, 43)),
    ])
def test_rule_repeat(src, expected):
    node, start = ABNFGrammarRule('repeat').parse(src, 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_repeat(node)
    assert (parser.min, parser.max) == expected

def test_repetition():
    parser = Repetition(Repeat(1, 2), Literal('a'))
    node, start = parser.parse('aa', 0)
    assert [x for x in flatten(node)] == [LiteralNode('a', x, 1) for x in range(0, 2)]

def test_repetition_str():
    parser = Repetition(Repeat(1, 2), Literal('a'))
    assert str(parser) == "Repetition(Repeat(1, 2), Literal('a'))"

@pytest.mark.parametrize("src", ['bc', 'a', pytest.param('ac', marks=pytest.mark.xfail)])
def test_operator_precedence(src):
    grammar_src = '"a" / "b" "c"'
    node, start = ABNFGrammarRule('alternation').parse(grammar_src, 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_alternation(node)
    node, start = parser.parse(src, 0)
    print(node)
    assert ''.join(x.value for x in flatten(node)) == src


@pytest.mark.parametrize("src", ['ac', 'bc'])
def test_operator_precedence_1(src):
    grammar_src = '("a" / "b") "c"'
    node, start = ABNFGrammarRule('concatenation').parse(grammar_src, 0)
    visitor = ABNFGrammarRuleNodeVisitor(None)
    parser = visitor.visit_concatenation(node)
    node, start = parser.parse(src, 0)
    print(node)
    assert ''.join(x.value for x in node) == src

def test_node_str():
    node_name = 'foo'
    node_children = []
    node = Node(name=node_name, *node_children)
    assert str(node) == 'Node(name=%s, children=%s)' % (node_name, str(node_children))

def test_node_eq():
    assert Node('foo') == Node('foo')
    
def test_literal_node_children():
    node = LiteralNode('', 0, 0)
    assert node.children == []
    
def test_visit_option_bad_node():
    node = Node('foo')
    visitor = ABNFGrammarRuleNodeVisitor(None)
    with pytest.raises(AssertionError):
        parser = visitor.visit_option(node)

def test_visit_group_bad_node():
    node = Node('foo')
    visitor = ABNFGrammarRuleNodeVisitor(None)
    with pytest.raises(AssertionError):
        parser = visitor.visit_group(node)

def test_Alternation_str():
    parser = Alternation(Literal('foo'), Literal('bar'))
    assert str(parser) == "Alternation(Literal('foo'), Literal('bar'))"

def test_Concatenation_str():
    parser = Concatenation(Literal('foo'), Literal('bar'))
    assert str(parser) == "Concatenation(Literal('foo'), Literal('bar'))"

def test_option_str():
    parser = Option(Alternation(Literal('foo')))
    assert str(parser) == "Option(Alternation(Literal('foo')))"

def test_rule_undefined():
    with pytest.raises(GrammarError):
        Rule('undefined').parse('x', 0)

def test_rule_str():
    assert str(Rule('ALPHA')) == "Rule('ALPHA')"

@pytest.mark.parametrize("src", ['a', 'b'])
def test_rule_def_alternation(src):
    class TestRule(Rule):
        pass

    rulelist = ['moof = "a"', 'moof =/ "b"']
    for rule in rulelist:
        TestRule.create(rule)

    node, start = TestRule('moof').parse(src, 0)
    assert node and node.value == src

def test_rule_bad_defined_as():
    node = Node('rule', *[Node('rulename', *[Node('ALPHA', *[LiteralNode('a', 0, 1)])]), Node('defined-as', *[LiteralNode("=\\", 1, 2)]), Node('elements', *[Node('alternation', *[Node('concatenation', *[Node('repetition', *[Node('element', *[Node('rulename', *[Node('ALPHA', *[LiteralNode('b', 3, 1)])])])])])])]), Node('c-nl', *[Node('CRLF', *[Node('CR', *[LiteralNode('\r', 4, 1)]), Node('LF', *[LiteralNode('\n', 5, 1)])])])])
    with pytest.raises(AssertionError):
        visitor = ABNFGrammarRuleNodeVisitor(ABNFGrammarRule)
        visitor.visit_rule(node)

class XRule(Rule):
    pass

# an XRule object is created, without definition.
XRule('foo')
        
def test_rule_rules():
    assert XRule.rules() == [XRule('foo')]

@pytest.mark.parametrize("name, rule", [('foo', XRule('foo')), ('bar', None)])
def test_rule_get(name, rule):
    assert XRule.get(name) is rule

def test_parse_all_pass():
    src = 'moof'
    node = ABNFGrammarRule('rulename').parse_all(src)
    assert node.value == src

def test_parse_all_fail():
    src = 'rule name'
    with pytest.raises(ParseError):
        ABNFGrammarRule('rulename').parse_all(src)

    