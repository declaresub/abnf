import pytest

from abnf.grammars import rfc7838


@pytest.mark.parametrize("field_value", [
    'clear',
    'h2="alt.example.com:443"; ma=2592000',
    'h2=":443"',
    'h2="alt.example.com:443", h2=":443"',
    'h3-25=":443"; ma=3600; persist=1',
    'h2="alt.example.com:8000"; ma=60, h2=":443"; ma=300',
])
def test_rfc7838_alt_svc(field_value):
    assert rfc7838.Rule("Alt-Svc").parse_all(field_value)


@pytest.mark.parametrize("field_value", [
    'alt.example.com:443',
    'alt.example.com',
    '192.0.2.1:443',
    '[2001:db8::1]:443',
])
def test_rfc7838_alt_used(field_value):
    assert rfc7838.Rule("Alt-Used").parse_all(field_value)
