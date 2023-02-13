import pytest

from abnf.grammars import rfc6266


@pytest.mark.parametrize(
    "src",
    [
        "Content-Disposition: inline",
        "Content-Disposition: attachment",
        'Content-Disposition: attachment; filename="filename.jpg"',
        'Content-Disposition: form-data; name="fieldName"',
        'Content-Disposition: form-data; name="fieldName"; filename="filename.jpg"',
        "Content-Disposition: attachment; filename*=UTF-8''%e2%82%ac%20rates",
        "Content-Disposition: attachment; filename=\"EURO rates\"; filename*=utf-8''%e2%82%ac%20rates",
    ],
)
def test_content_disposition(src: str):
    content_disposition = rfc6266.Rule("content-disposition")
    assert content_disposition.parse_all(src)
