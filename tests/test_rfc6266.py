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


def test_disp_ext_parm():
    # this test checks to ensure that the RFC 6266 grammar as modified in response to erratum
    # parses src into an ext-name = ext-value parameter.
    src = "foo*=utf-8''%E2%88%Aar"
    node = rfc6266.Rule("disp-ext-parm").parse_all(src)
    assert len(node.children) == 3
    assert node.children[0].name == "ext-parmname"
    assert node.children[0].value == "foo*"
    assert node.children[1].value == "="
    assert node.children[2].name == "ext-value"
    assert node.children[2].value == "utf-8''%E2%88%Aar"
