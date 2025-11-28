import pytest

from abnf.grammars import rfc7239


@pytest.mark.parametrize("field_value", [
    'for="_gazonk"',
    'For="[2001:db8:cafe::17]:4711"',
    'for=192.0.2.60;proto=http;by=203.0.113.43',
    'for=192.0.2.43, for=198.51.100.17',
    'for=unknown',
    'for=_hidden, for=_SEVKISEK',
    'for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown',
    ])
def test_rfc7239_simple_examples(field_value):
    assert rfc7239.Rule("Forwarded").parse_all(field_value)
