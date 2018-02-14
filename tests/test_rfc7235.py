import pytest

from abnf.grammars import rfc7235

@pytest.mark.parametrize("src", [
    'Basic realm="/"',
    'Basic bW9vZgo=',
    ])
def test_rfc7235_challenge(src):
    assert rfc7235.Rule('challenge').parse_all(src)
    
@pytest.mark.parametrize("src", ['Basic realm="/"', 'Basic bW9vZgo='])
def test_rfc7235_credentials(src):
    assert rfc7235.Rule('credentials').parse_all(src)

@pytest.mark.parametrize("src", [
    'Basic realm="/"',
    'Basic bW9vZgo=',
    'Newauth realm="apps", type=1, title="Login to \\"apps\\"", Basic realm="simple"'
    ])    
def test_rfc7235_www_authenticate(src):
    assert rfc7235.Rule('WWW-Authenticate').parse_all(src)