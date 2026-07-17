import pytest

from abnf import ParseError
from abnf.grammars import rfc8288


@pytest.mark.parametrize("field_value", [
    '<https://example.com/page2>; rel="next"',
    '<https://example.com>; rel="previous"; title="prev"',
    '<http://example.org/>; rel="start http://example.net/relation/other"',
    '</TheBook/chapter2>; rel="previous"; title*=UTF-8\'de\'letztes%20Kapitel, '
    '</TheBook/chapter4>; rel="next"; title*=UTF-8\'de\'n%C3%A4chstes%20Kapitel',
    '</>; rel="http://example.net/foo"',
    '<https://example.com/;type=whatever>; rel=next; anchor="#foo"',
    '',  # #rule permits an empty list
])
def test_rfc8288_link(field_value):
    assert rfc8288.Rule("Link").parse_all(field_value)


@pytest.mark.parametrize("field_value", [
    'https://example.com; rel="next"',   # URI-Reference must be enclosed in <>
    '<https://example.com> rel="next"',  # missing ";" separator
])
def test_rfc8288_link_fail(field_value):
    with pytest.raises(ParseError):
        rfc8288.Rule("Link").parse_all(field_value)
