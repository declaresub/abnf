import pytest

from abnf.grammars import rfc7240
from abnf.parser import ParseError


@pytest.mark.parametrize("field_value", [
    "Prefer: respond-async",
    "Prefer: respond-async, wait=100",
    "Prefer: wait=100",
    "Prefer: return=representation",
    "Prefer: return=minimal",
    "Prefer: handling=strict",
    "Prefer: handling=lenient",
    "Prefer: return=representation; wait=10",
    'Prefer: foo; bar; baz=quux',
    'Prefer: lenient, respond-async',
    ])
def test_rfc7240_prefer(field_value):
    assert rfc7240.Rule("Prefer").parse_all(field_value)


@pytest.mark.parametrize("field_value", [
    "Preference-Applied: return=representation",
    "Preference-Applied: return=minimal",
    "Preference-Applied: return=representation, wait=10",
    ])
def test_rfc7240_preference_applied(field_value):
    assert rfc7240.Rule("Preference-Applied").parse_all(field_value)


@pytest.mark.parametrize("src", [
    "return=representation",
    "wait=100",
    "respond-async",
    'foo="bar baz"',
    ])
def test_rfc7240_preference(src):
    assert rfc7240.Rule("preference").parse_all(src)


# Issue #237: Preference-Applied was built from `preference`, which permits
# parameters.  RFC 7240 section 3 defines it over `applied-pref` and says the
# syntax "differs from that of the Prefer header in that parameters are not
# included".
@pytest.mark.parametrize(
    'src',
    [
        'Preference-Applied: respond-async',
        'Preference-Applied: return=minimal',
        'Preference-Applied: respond-async, wait=10',   # a list is still fine
    ],
)
def test_237_preference_applied_accepts(src: str):
    assert rfc7240.Rule('Preference-Applied').parse_all(src).value == src


def test_237_preference_applied_rejects_parameters():
    with pytest.raises(ParseError):
        rfc7240.Rule('Preference-Applied').parse_all(
            'Preference-Applied: respond-async; wait=10'
        )


def test_237_prefer_still_accepts_parameters():
    """The distinction only means something if Prefer keeps them."""
    src = 'Prefer: respond-async; wait=10'
    assert rfc7240.Rule('Prefer').parse_all(src).value == src
