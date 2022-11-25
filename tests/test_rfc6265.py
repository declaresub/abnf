import pytest

from abnf.grammars import rfc6265


@pytest.mark.parametrize("src", [
    'bar',
    '"bar"',
    ])
def test_cookie_value(src: str):
    rfc6265.Rule('cookie-value').parse_all(src)


@pytest.mark.parametrize("src", [
    "www.example.com",
    "127.0.0.1",
    "FE80:CD00:0000:0CDE:1257:0000:211E:729C"
])
def test_domain_value(src: str):
    node = rfc6265.Rule('domain-value').parse_all(src)
    assert node.value == src