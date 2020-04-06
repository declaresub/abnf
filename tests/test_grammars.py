import pytest
import abnf.grammars
import pkgutil
from importlib import import_module

@pytest.mark.parametrize("rfc", map(import_module, ['%s.%s' % (abnf.grammars.__name__, x[1]) for x in pkgutil.walk_packages(abnf.grammars.__path__) if x[1] == 'cors' or x[1].startswith('rfc')]))
def test_grammar(rfc):
    """Catches rules used but not defined in grammar."""
    for rule in rfc.Rule.rules():
        if not hasattr(rule, 'definition'):
            print(str(rule))
        assert hasattr(rule, 'definition')
