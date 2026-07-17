import warnings

import pytest

from abnf.parser import GrammarWarning, ParseError, Rule


def test_case_insensitive_redefinition_warns():
    class R(Rule):
        pass

    R.create("Origin = %x61")
    with pytest.warns(GrammarWarning, match="differs only in case"):
        R.create("origin = %x62")


def test_same_name_redefinition_warns():
    class R(Rule):
        pass

    R.create("foo = %x61")
    with pytest.warns(GrammarWarning, match="redefines 'foo'"):
        R.create("foo = %x62")


def test_incremental_alternative_does_not_warn():
    class R(Rule):
        pass

    R.create("foo = %x61")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GrammarWarning)
        R.create("foo =/ %x62")


def test_forward_reference_does_not_warn():
    class R(Rule):
        pass

    with warnings.catch_warnings():
        warnings.simplefilter("error", GrammarWarning)
        R.create("bar = foo")
        R.create("foo = %x61")


def test_redefinition_keeps_latest_definition():
    class R(Rule):
        pass

    R.create("foo = %x61")
    with pytest.warns(GrammarWarning):
        R.create("foo = %x62")
    # 'b' (%x62), the later definition, is what remains.
    assert R("foo").parse_all("b")
    with pytest.raises(ParseError):
        R("foo").parse_all("a")
