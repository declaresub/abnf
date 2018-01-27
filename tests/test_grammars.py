import pytest
from abnf.grammars import rfc3986, rfc4647, rfc5322, rfc5646, rfc7230, rfc7231, rfc7232


@pytest.mark.parametrize("rfc", [rfc3986, rfc4647, rfc5322, rfc5646, rfc7230, rfc7231, rfc7232])
def test_grammar_creation(rfc):
    print(rfc)
    for rule_src in rfc.Rule.grammar:
        rulename = rule_src.split(' ', 1)[0]
        assert rfc.Rule(rulename) and rfc.Rule(rulename).definition
