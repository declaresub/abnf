import pytest

from abnf.grammars import rfc3987


def test_ipath_empty():
    # ipath-empty definition uses the prose-val as rulename thing,
    # so we check to ensure that parsing succeeds.

    src = ""
    node = rfc3987.Rule("ipath-empty").parse_all(src)
    assert node.value == src


# Issue #232: every rule in this module used to be set to
# `first_match_alternation` in a loop, which had the same effect as the
# equivalent setting in rfc3986 -- `ihost` committed to IPv4address on a
# prefix, so an IRI whose host merely begins like an IPv4 address was
# rejected.
@pytest.mark.parametrize(
    'src',
    [
        'https://1.2.3.4.in-addr.arpa/',
        'http://1.2.3.4.5/',
        'https://1.2.3.4.\u4f8b\u3048.jp/',
    ],
)
def test_232_ihosts_that_start_like_an_ipv4_address(src: str):
    assert rfc3987.Rule('IRI').parse_all(src).value == src


@pytest.mark.parametrize(
    'src',
    [
        'http://ex\u00e4mple.com/\u00fcnicode?q=\u00e9#frag',
        'https://\u4f8b\u3048.jp/\u9053',
        'https://user:pw@\u4f8b\u3048.jp:8080/\u9053?q=1#f',
        'http://1.2.3.4/',
    ],
)
def test_232_ordinary_iris_are_unaffected(src: str):
    assert rfc3987.Rule('IRI').parse_all(src).value == src
