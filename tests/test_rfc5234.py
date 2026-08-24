import pytest

from abnf.grammars import rfc5234
from abnf.parser import ParseError


# Issue #237: `element` dropped the `prose-val` alternative RFC 5234 section 4
# gives it.
@pytest.mark.parametrize(
    'src',
    ['<some prose>', 'rulename', '"literal"', '%x41', '(group)', '[option]'],
)
def test_237_element_alternatives(src: str):
    assert rfc5234.Rule('element').parse_all(src).value == src


@pytest.mark.parametrize('src', ['<', '', '/'])
def test_237_element_rejects(src: str):
    with pytest.raises(ParseError):
        rfc5234.Rule('element').parse_all(src)
