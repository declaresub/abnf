import pytest

from abnf.grammars import rfc6265


@pytest.mark.parametrize("src", [
    'bar',
    '"bar"',
    ])
def test_cookie_value(src):
    rfc6265.Rule('cookie-value').parse_all(src)