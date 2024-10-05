import pytest

from abnf.grammars.misc import load_grammar_rulelist, load_grammar_rules
from abnf.parser import Literal
from abnf.parser import Rule as _Rule


class ImportRule(_Rule):
    pass


ImportRule("test", Literal("test"))


@load_grammar_rules([("test", ImportRule("test"))])
class Rule(_Rule):
    grammar = []


def test_misc_load_grammar_rules_import():
    assert Rule("test").definition == ImportRule("test").definition


@load_grammar_rulelist([("test", ImportRule("test"))])
class Rule1(_Rule):
    grammar = ''

def test_load_grammar():
    assert Rule("test").definition == ImportRule("test").definition


class Foo(_Rule):
    grammar = 'foo="bar"'


def test_load_grammar_rules_str():
    with pytest.raises(TypeError):
        load_grammar_rules()(Foo)
