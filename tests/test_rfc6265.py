import pytest

from abnf.grammars import rfc6265


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
