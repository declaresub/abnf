import pytest

from abnf.grammars import rfc6797


@pytest.mark.parametrize("field_value", [
    "Strict-Transport-Security: max-age=31536000",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    'Strict-Transport-Security: max-age="31536000"',
    "Strict-Transport-Security: max-age=0",
    "Strict-Transport-Security:max-age=31536000;includeSubDomains",
])
def test_rfc6797_sts(field_value):
    assert rfc6797.Rule("Strict-Transport-Security").parse_all(field_value)


@pytest.mark.parametrize("src", [
    "max-age=31536000",
    "includeSubDomains",
    'foo="bar"',
])
def test_rfc6797_directive(src):
    assert rfc6797.Rule("directive").parse_all(src)
