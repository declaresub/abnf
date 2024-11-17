import pytest

from abnf.grammars import rfc3339


# dates taken from RFC 3339
@pytest.mark.parametrize(
    "src",
    [
        "1985-04-12T23:20:50.52Z",
        "1996-12-19T16:39:57-08:00",
        "1990-12-31T23:59:60Z",
        "1990-12-31T15:59:60-08:00",
        "1937-01-01T12:00:27.87+00:20",
    ],
)
def test_parse_datetime(src: str):
    assert rfc3339.Rule("date-time").parse_all(src)
