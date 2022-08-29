import pytest

from abnf.grammars import rfc5987


# this test feeds a few examples from RFC 5987 into the parser to see they
# are in fact parsed.
@pytest.mark.parametrize("src", [
'title=Economy',
'title="US-$ rates"',
'title*=iso-8859-1\'en\'%A3%20rates',
])
def test_parse_parameter(src: str):
    rfc5987.Rule("parameter").parse_all(src)
