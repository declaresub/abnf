import pytest

from abnf.grammars import rfc7240


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
