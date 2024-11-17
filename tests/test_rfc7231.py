import pytest

from abnf.grammars import rfc7231
from abnf.parser import Source


@pytest.mark.parametrize(
    "src",
    [
        "*/*",
        "text/html",
        "image/*",
        "text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8",
    ],
)
def test_accept_parse(src: Source):
    accept = rfc7231.Rule("accept")
    assert accept.parse_all(src)


@pytest.mark.parametrize(
    "src",
    [
        "Wed, 21 Oct 2015 07:28:00 GMT",
        "Tuesday, 08-Feb-94 14:15:29 GMT",
        "Thu Feb  3 00:00:00 1994",
    ],
)
def test_date_parse(src: Source):
    date = rfc7231.Rule("Date")
    assert date.parse_all(src)
