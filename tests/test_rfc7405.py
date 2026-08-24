import pytest

from abnf.grammars import rfc5234, rfc7405
from abnf.parser import ParseError


# Issue #244: this module exists to extend RFC 5234's char-val with the
# case-sensitive (%s) and case-insensitive (%i) forms, and it had no test
# file at all -- nothing checked that it could.  It always could; #244 was
# reported on a misreading of the import comprehension, which looks like it
# would shadow `char-val` but is evaluated before `rfc5234` holds that name.
#
# The tests remain worth having.  They pin the extension at every level, so a
# change anywhere in the chain from `rulelist` down to `char-val` -- including
# an import list that really does shadow it -- fails here.


def test_244_char_val_is_the_modules_own_rule():
    assert (
        rfc7405.Rule('char-val').definition
        is not rfc5234.Rule('char-val').definition
    )


@pytest.mark.parametrize('src', ['%s"abc"', '%i"abc"', '"abc"'])
def test_244_char_val_forms(src: str):
    assert rfc7405.Rule('char-val').parse_all(src).value == src


@pytest.mark.parametrize('src', ['%z"abc"', '%s abc', '%s'])
def test_244_char_val_rejects(src: str):
    with pytest.raises(ParseError):
        rfc7405.Rule('char-val').parse_all(src)


# The extension has to be visible from the rules above char-val too.  Those
# rules cannot be imported from rfc5234: an imported rule refers to that
# module's objects, so it would reach RFC 5234's plain char-val.
@pytest.mark.parametrize('src', ['%s"abc"', '%i"abc"', '"abc"', 'rulename', '(rulename)'])
def test_244_element_sees_the_extension(src: str):
    assert rfc7405.Rule('element').parse_all(src).value == src


@pytest.mark.parametrize(
    'src',
    ['a = %s"abc"\r\n', 'a = %i"abc"\r\n', 'a = "abc"\r\n', 'a = %s"x" / %i"y"\r\n'],
)
def test_244_rule_sees_the_extension(src: str):
    assert rfc7405.Rule('rule').parse_all(src).value == src


def test_244_rulelist_sees_the_extension():
    src = 'a = %s"x"\r\nb = a / %i"y"\r\n'
    assert rfc7405.Rule('rulelist').parse_all(src).value == src


def test_244_case_sensitivity_is_what_the_rfc_says():
    """%s is case-sensitive, %i case-insensitive -- the distinction the
    RFC adds.  Both are still just syntax here; this pins that each form
    parses and reports which one it matched."""
    node = rfc7405.Rule('char-val').parse_all('%s"abc"')
    assert 'case-sensitive-string' in [c.name for c in node.children]

    node = rfc7405.Rule('char-val').parse_all('%i"abc"')
    assert 'case-insensitive-string' in [c.name for c in node.children]
