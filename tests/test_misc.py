from abnf.parser import Rule as _Rule, Literal
from abnf.grammars.misc import load_grammar_rules


class ImportRule(_Rule):
    pass
    
ImportRule('test', Literal('test'))    


@load_grammar_rules(
[
('test', ImportRule('test'))
])
class Rule(_Rule):
    """Rules from RFC 5646."""

    grammar = []

def test_misc_load_grammar_rules_import():
    assert Rule('test').definition == ImportRule('test').definition
