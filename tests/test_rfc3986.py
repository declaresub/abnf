import pytest

from abnf.grammars import rfc3986


@pytest.mark.parametrize('src, value', [
# test added thanks to https://github.com/declaresub/abnf/issues/10.
('2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:0db8:0000:0000:0000:ff00:0042:8329'), 
('2001:db8:cafe::17', '2001:db8:cafe::17'),
('0:0:0:0:0:ffff:192.1.56.10', '0:0:0:0:0:ffff:192.1.56.10'),
('::', '::'),
])
def test_IPv6address(src: str, value: str):
    ip6 = rfc3986.Rule('IPv6address')
    assert ip6.parse_all(src).value == value
