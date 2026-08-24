import pytest

from abnf.grammars import rfc2616
from abnf.parser import ParseError


def test_token():
    # exercise rule imported by hand from RFC 2616.
    src = "token"
    assert rfc2616.Rule("token").parse_all(src)


# Issue #236: token was transcribed from prose (<any CHAR except CTLs or
# separators>) into explicit ranges, and the conversion dropped %x7E.  "~" is
# not a separator, so it belongs.  rfc6265 imports this rule for cookie-name,
# so the omission reached cookie parsing too.
@pytest.mark.parametrize('src', ['~foo', 'foo~', 'a~b', '~', 'text', 'a|b', "a'b"])
def test_236_token_accepts(src: str):
    assert rfc2616.Rule('token').parse_all(src).value == src


@pytest.mark.parametrize(
    'src',
    ['a b', 'a,b', 'a/b', 'a{b', 'a}b', 'a:b', 'a"b', 'a@b', 'a[b', 'a?b', 'a=b'],
)
def test_236_token_still_rejects_separators(src: str):
    with pytest.raises(ParseError):
        rfc2616.Rule('token').parse_all(src)


def test_236_token_agrees_with_rfc7230_tchar():
    """RFC 7230's tchar is the same character set, transcribed
    independently in another module -- so the two must accept exactly the
    same characters."""
    from abnf.grammars import rfc7230

    def accepts(rule, char: str) -> bool:
        try:
            rule.parse_all(char)
        except ParseError:
            return False
        return True

    old = rfc2616.Rule('token')
    new = rfc7230.Rule('token')
    disagree = [
        chr(c) for c in range(0x20, 0x7F) if accepts(old, chr(c)) != accepts(new, chr(c))
    ]
    assert not disagree
