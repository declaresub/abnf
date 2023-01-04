from abnf.grammars import rfc2616


def test_token():
    # exercise rule imported by hand from RFC 2616.
    src = "token"
    assert rfc2616.Rule("token").parse_all(src)
