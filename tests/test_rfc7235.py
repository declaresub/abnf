import pytest

from abnf.grammars import rfc7235
from abnf.parser import ParseError


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


# Issue #237: both headers once carried a workaround for the ambiguity in
# RFC 7235's expansion -- `challenge` can consume a trailing comma.  9c4ab8f
# (2022) found the parser handled the rule as written and reverted
# WWW-Authenticate, but left Proxy-Authenticate on the workaround, so the two
# accepted different languages for grammar the RFC defines identically.
@pytest.mark.parametrize('rule', ['Proxy-Authenticate', 'WWW-Authenticate'])
@pytest.mark.parametrize(
    'src',
    [
        'Basic realm="a"',
        # the case the 2022 comment said was mishandled
        'Basic realm="foo", Pascal realm="bar"',
        'Newauth realm="apps", type=1, title="Login to apps", Basic realm="simple"',
    ],
)
def test_237_challenge_lists(rule: str, src: str):
    assert rfc7235.Rule(rule).parse_all(src).value == src


@pytest.mark.parametrize('rule', ['Proxy-Authenticate', 'WWW-Authenticate'])
def test_237_challenges_must_be_comma_separated(rule: str):
    """The two rules have identical grammar in the RFC, so they must
    accept identical languages -- this was accepted by one and not the
    other."""
    with pytest.raises(ParseError):
        rfc7235.Rule(rule).parse_all('Basic realm="a" Newauth realm="b"')
