import pytest
from abnf.parser import *

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
    visitor = CharValNodeVisitor()
    parser = visitor.visit_char_val(node)
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value == src

@pytest.mark.parametrize("src", ['moof', 'MOOF', 'mOOf', 'mOoF'])
def test_char_val_case_insensitive(src):
    node, start = ABNFGrammarRule('char-val').parse('%i"moof"', 0)
    visitor = CharValNodeVisitor()
    parser = visitor.visit_char_val(node)
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value.casefold() == 'moof'

def test_char_val_case_sensitive():
    node, start = ABNFGrammarRule('char-val').parse('%s"MOOF"', 0)
    visitor = CharValNodeVisitor()
    parser = visitor.visit_char_val(node)
    src = 'MOOF'
    char_node, start = parser.parse(src, 0)
    assert char_node and char_node.value == src

@pytest.mark.parametrize("src", ['MOOF', 'mOOf', 'mOoF'])
def test_char_val_case_sensitive_fail(src):
    node, start = ABNFGrammarRule('char-val').parse('%s"moof"', 0)
    visitor = CharValNodeVisitor()
    parser = visitor.visit_char_val(node)
    with pytest.raises(ParseError):
        parser.parse(src, 0)

def test_bin_val():
    src = "b01111000"
    node = ABNFGrammarRule('bin-val').parse_all(src)
    visitor = NumValVisitor()
    parser = visitor.visit(node)
    assert parser.value == 'x'

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
    visitor = ABNFGrammarNodeVisitor(ABNFGrammarRule)
    parser = visitor.visit_repeat(node)
    assert (parser.min, parser.max) == expected

def test_repetition():
    parser = Repetition(Repeat(1, 2), Literal('a'))
    node, start = parser.parse('aa', 0)
    assert [x for x in flatten(node)] == [LiteralNode('a', x, 1) for x in range(0, 2)]

def test_repetition_str():
    parser = Repetition(Repeat(1, 2), Literal('a'))
    assert str(parser) == "Repetition(Repeat(1, 2), Literal('a'))"

# concatenation has higher precedence than alternation; the next few tests confirm this.
@pytest.mark.parametrize("src", ['bc', 'a'])
def test_operator_precedence(src):
    grammar_src = '"a" / "b" "c"'
    node, start = ABNFGrammarRule('alternation').parse(grammar_src, 0)
    visitor = ABNFGrammarNodeVisitor(ABNFGrammarRule)
    parser = visitor.visit_alternation(node)
    node, start = parser.parse(src, 0)
    assert ''.join(x.value for x in flatten(node)) == src

@pytest.mark.parametrize("src", ['ac'])
def test_operator_precedence_1(src):
    grammar_src = '"a" / "b" "c"'
    node, start = ABNFGrammarRule('alternation').parse(grammar_src, 0)
    visitor = ABNFGrammarNodeVisitor(ABNFGrammarRule)
    parser = visitor.visit_alternation(node)
    node, start = parser.parse(src, 0)
    assert node.value == 'a'

@pytest.mark.parametrize("src", ['ac', 'bc'])
def test_operator_precedence_2(src):
    grammar_src = '("a" / "b") "c"'
    node, start = ABNFGrammarRule('concatenation').parse(grammar_src, 0)
    visitor = ABNFGrammarNodeVisitor(ABNFGrammarRule)
    parser = visitor.visit_concatenation(node)
    node, start = parser.parse(src, 0)
    assert ''.join(x.value for x in node) == src

def test_node_str():
    node_name = 'foo'
    node_children = []
    node = Node(name=node_name, *node_children)
    assert str(node) == 'Node(name=%s, children=%s)' % (node_name, str(node_children))

def test_node_eq():
    assert Node('foo') == Node('foo')
    
    
def test_literal_node_str():
    # test just exercises Node.__str__.
    node = LiteralNode('a', 1, 2)
    assert str(node)

def test_literal_node_children():
    node = LiteralNode('', 0, 0)
    assert node.children == []

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

@pytest.mark.parametrize("num_val", ['%x2227', '%d8743', '%b0010001000100111'])
def test_unicode_num_val(num_val):
    # https://github.com/declaresub/abnf/issues/1
    class TestRule(Rule):
        pass

    value = '∧'
    rule = 'combine = %s' % num_val
    combine = TestRule.create(rule)
    node = combine.parse_all(value)
    assert node.value == value

def test_unicode_hex_val_concat():
    class TestRule(Rule):
        pass

    value = 'Я́блоко'
    rule = 'apple = %x42f.301.431.43b.43e.43a.43e'
    combine = TestRule.create(rule)
    print(str(combine.definition))
    node = combine.parse_all(value)

    assert node.value == value

def test_from_file(tmp_path):
    grammar = ['foo = "foo"\r\n', 'bar = "bar"\r\n']
    path = tmp_path / 'test_grammar.abnf'
    path.write_text(''.join(grammar))
    
    class FromFileRule(Rule):
        pass
        
    FromFileRule.from_file(path)
    
@pytest.mark.parametrize("first_match, value", [(True, 'foo'), (False, 'foobar')])
def test_alternation_first_match(first_match, value):
    src = 'foobar'
    parser = Alternation(Literal('foo'), Literal('foobar'), first_match=first_match)
    node, start = parser.parse(src, 0)
    assert node.value == value

def test_alternation_first_match1():
    src = 'bar'
    parser = Alternation(Literal('foo'), Literal('bar'), first_match=True)
    node, start = parser.parse(src, 0)
    assert node.value == src

def test_alternation_first_match_fail():
    src = 'moof'
    parser = Alternation(Literal('foo'), Literal('bar'), first_match=True)
    with pytest.raises(ParseError):
        parser.parse(src, 0)

def test_exclude_rule_identifier():
    class ExcludeRule(Rule):
        pass

    ExcludeRule.create('foo = %x66.6f.6f')
    ExcludeRule.create('keyword = foo')
    ExcludeRule.create('identifier = ALPHA *(ALPHA / DIGIT )')
    keyword = ExcludeRule('keyword')
    identifier = ExcludeRule('identifier')
    identifier.exclude_rule(keyword)
    src = 'foo1'
    node, start =  identifier.parse(src, 0)
    assert node.value == src and start == 4
        
def test_exclude_rule_keyword():
    class ExcludeRule(Rule):
        pass

    ExcludeRule.create('foo = %x66.6f.6f')
    ExcludeRule.create('keyword = foo')
    ExcludeRule.create('identifier = ALPHA *(ALPHA / DIGIT )')
    keyword = ExcludeRule('keyword')
    identifier = ExcludeRule('identifier')
    identifier.exclude_rule(keyword)
    src = 'foo'
    with pytest.raises(ParseError):
        identifier.parse(src, 0)

@pytest.mark.parametrize("args", [(None, 1), (Literal('a'), None)])
def test_parseerror_bad_args(args):
    with pytest.raises(ValueError):
        ParseError(*args)

def test_parseerror_str():
    # I'm not checking the output, just exercising ParseError.__str__ .
    assert str(ParseError(Literal('a'), 1))


def test_prose_val():
    class TestRule(Rule):
        pass
        
    rule = 'test-prose-val = <blah blah>'
    with pytest.raises(GrammarError):
        TestRule.create(rule)
