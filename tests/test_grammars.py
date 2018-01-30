import pytest
import abnf.grammars
import pkgutil
from importlib import import_module

@pytest.mark.parametrize("rfc", map(import_module, ['%s.%s' % (abnf.grammars.__name__, x[1]) for x in pkgutil.walk_packages(abnf.grammars.__path__) if x[1].startswith('rfc')]))
def test_grammar_creation(rfc):
    print(rfc)
    for rule_src in rfc.Rule.grammar:
        rulename = rule_src.split(' ', 1)[0]
        assert rfc.Rule(rulename) and rfc.Rule(rulename).definition
