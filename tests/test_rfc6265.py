import pytest

from abnf.grammars import rfc6265
from abnf.parser import ParseError


@pytest.mark.parametrize("src", [
    "a",
    "1",
])
def test_letdig(src: str):
    node = rfc6265.LocalRule('let-dig').parse_all(src)
    assert node.value == src


@pytest.mark.parametrize("src", [
    "a-",
    "1-",
    "a-1",
])
def test_ldh_str(src: str):
    node = rfc6265.LocalRule('ldh-str').parse_all(src)
    assert node.value == src

@pytest.mark.parametrize("src", [
    "test",
    "a-1",
])
def test_label(src: str):
    node = rfc6265.LocalRule('label').parse_all(src)
    assert node.value == src

@pytest.mark.parametrize("src", [
    "test",
    "example.com",
])
def test_subdomain(src: str):
    node = rfc6265.LocalRule('subdomain').parse_all(src)
    assert node.value == src



@pytest.mark.parametrize("src", [
    "www.example.com",
    "127.0.0.1",
    "FE80:CD00:0000:0CDE:1257:0000:211E:729C"
])
def test_domain_value(src: str):
    node = rfc6265.LocalRule('domain-value').parse_all(src)
    assert node.value == src


def _av_names(header: str) -> list[str]:
    """Which attribute rules the parse tree actually used."""
    node = rfc6265.Rule('set-cookie-string').parse_all(header)
    found: list[str] = []

    def walk(n):
        name = getattr(n, 'name', '')
        if name.endswith('-av') and name != 'cookie-av':
            found.append(name)
        for child in getattr(n, 'children', None) or ():
            walk(child)

    walk(node)
    return found


# Issue #235: domain-value is <subdomain> "as enhanced by [RFC1123], Section
# 2.1", and that section relaxes the first character to "either a letter or a
# digit".  The module transcribed plain RFC 1034, so a digit-leading domain was
# rejected -- and at header level it did not fail, it silently fell through to
# extension-av, so a consumer looking for the Domain attribute found nothing.
@pytest.mark.parametrize(
    'src',
    ['365online.com', '3com.com', 'example.com', 'a-b.example.com', 'x1.y2.example'],
)
def test_235_domain_value_allows_a_leading_digit(src: str):
    assert rfc6265.Rule('domain-value').parse_all(src).value == src


@pytest.mark.parametrize(
    'header, expected',
    [
        ('id=a; Domain=365online.com', 'domain-av'),
        ('id=a; Domain=example.com', 'domain-av'),
        ('id=a; Path=/', 'path-av'),
        ('id=a; Path=', 'path-av'),          # erratum 3444: path-value is *, not 1*
        ('id=a; Max-Age=60', 'max-age-av'),
        ('id=a; Secure', 'secure-av'),
        ('id=a; Frobnicate=1', 'extension-av'),   # genuinely unknown, still falls through
    ],
)
def test_235_attributes_are_labelled_not_swallowed(header: str, expected: str):
    assert expected in _av_names(header)


@pytest.mark.parametrize('src', ['-example.com', '.example.com', ''])
def test_235_domain_value_still_rejects(src: str):
    """Relaxing the first character must not relax the rest."""
    with pytest.raises(ParseError):
        rfc6265.Rule('domain-value').parse_all(src)


@pytest.mark.parametrize('src', ['~x=1', 'a=1', 'a~b=1'])
def test_236_cookie_name_may_contain_a_tilde(src: str):
    """cookie-name is rfc2616's token, which was missing "~" (#236)."""
    assert rfc6265.Rule('cookie-pair').parse_all(src).value == src
