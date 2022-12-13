from abnf.grammars import rfc3987


def test_ipath_empty():
    # ipath-empty definition uses the prose-val as rulename thing,
    # so we check to ensure that parsing succeeds.

    src = ""
    node = rfc3987.Rule("ipath-empty").parse_all(src)
    assert node.value == src
