import pytest

from abnf import ParseError
from abnf.grammars import cors


@pytest.mark.parametrize("field_value", [
    "null",  # opaque origin serializes to the ASCII string "null"
    "https://example.com",
    "https://example.com:8080",
    "http://foo.invalid",
    "https://127.0.0.1:443",
    "https://[2001:db8::1]:8080",
    "https://[::1]",
    "ftp://a.b.c",
])
def test_cors_origin(field_value):
    assert cors.Rule("Origin").parse_all(field_value)


@pytest.mark.parametrize("field_value", [
    "NULL",  # origin-or-null "null" is case-sensitive (%s"null")
    "https://Example.com",  # serialized-domain is lowercase only
    "example.com",  # missing scheme "://"
    "",
])
def test_cors_origin_fail(field_value):
    with pytest.raises(ParseError):
        cors.Rule("Origin").parse_all(field_value)


def test_cors_serialized_origin_rejects_null():
    # "null" is only accepted at the origin-or-null level, not as a serialized origin.
    with pytest.raises(ParseError):
        cors.Rule("serialized-origin").parse_all("null")


@pytest.mark.parametrize("field_value", [
    "null",
    "*",
    "https://example.com",
])
def test_cors_allow_origin(field_value):
    assert cors.Rule("Access-Control-Allow-Origin").parse_all(field_value)


@pytest.mark.parametrize("field_value", ["true"])
def test_cors_allow_credentials(field_value):
    assert cors.Rule("Access-Control-Allow-Credentials").parse_all(field_value)


@pytest.mark.parametrize("field_value", ["false", "TRUE"])
def test_cors_allow_credentials_fail(field_value):
    with pytest.raises(ParseError):
        cors.Rule("Access-Control-Allow-Credentials").parse_all(field_value)


def test_cors_request_method():
    assert cors.Rule("Access-Control-Request-Method").parse_all("GET")


@pytest.mark.parametrize("field_value", ["X-Custom", "X-A, X-B"])
def test_cors_request_headers(field_value):
    assert cors.Rule("Access-Control-Request-Headers").parse_all(field_value)


@pytest.mark.parametrize("field_value", [
    "",  # #field-name permits an empty list
    "X-A",
    "X-A, X-B",
])
def test_cors_expose_headers(field_value):
    assert cors.Rule("Access-Control-Expose-Headers").parse_all(field_value)


def test_cors_max_age():
    assert cors.Rule("Access-Control-Max-Age").parse_all("3600")


@pytest.mark.parametrize("field_value", ["", "GET", "GET, POST"])
def test_cors_allow_methods(field_value):
    assert cors.Rule("Access-Control-Allow-Methods").parse_all(field_value)
