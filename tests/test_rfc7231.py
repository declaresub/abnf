import pytest

from abnf.grammars import rfc7231

@pytest.mark.parametrize("src", [
'*/*',
'text/html',
'image/*',
'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8'
])
def test_accept_parse(src):
    accept = rfc7231.Rule('accept')
    assert accept.parse_all(src)
