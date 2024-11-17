import pytest

from abnf.grammars import rfc7235


@pytest.mark.parametrize("src", [
    'Basic bW9vZgo=',
    'Digest username="Mufasa", realm="http-auth@example.org", uri="/dir/index.html", algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", qop=auth, response="8ca523f5e9506fed4657c9700eebdbec", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
    ])
def test_rfc7235_credentials(src: str):
    assert rfc7235.Rule('Authorization').parse_all(src)

@pytest.mark.parametrize("src", [
    'Basic realm="/"',
    'Basic bW9vZgo=',
    'Newauth realm="apps", type=1, title="Login to \\"apps\\"", Basic realm="simple"'
    ])    
def test_rfc7235_www_authenticate(src: str):
    assert rfc7235.Rule('WWW-Authenticate').parse_all(src)
