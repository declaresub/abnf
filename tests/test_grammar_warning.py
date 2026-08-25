import subprocess
import sys
import warnings

import pytest

from abnf.grammars.misc import _apply_imports
from abnf.parser import GrammarError, GrammarWarning, ParseError, Rule


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


# Issue #246: imports are applied after the grammar text, so an imported rule
# replaces a definition of the same name.  That is the intended mechanism --
# a module writes a rule it does not own as prose and lets the import supply
# the real one -- but nothing distinguished it from an import clobbering real
# grammar by accident, which is how #234 got in and stayed in.
def _source_module(rules: str) -> type[Rule]:
    class Source(Rule):
        pass

    for line in rules.splitlines():
        Source.create(line)
    return Source


def test_246_import_over_prose_is_silent():
    """The legitimate pattern: declare a rule as prose, import the real one."""

    source = _source_module("token = %x61")

    class R(Rule):
        pass

    R.create("token = <token, defined elsewhere>")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GrammarWarning)
        _apply_imports(R, [("token", source("token"))])
    assert R("token").parse_all("a")


def test_246_import_over_real_grammar_warns():
    source = _source_module("atom = %x61")

    class R(Rule):
        pass

    R.create("atom = %x62")
    with pytest.warns(GrammarWarning, match='importing "atom"'):
        _apply_imports(R, [("atom", source("atom"))])


def test_246_import_of_an_undefined_name_is_silent():
    """Importing a name the module never mentions is the common case."""

    source = _source_module("UTF8-2 = %x61")

    class R(Rule):
        pass

    with warnings.catch_warnings():
        warnings.simplefilter("error", GrammarWarning)
        _apply_imports(R, [("UTF8-2", source("UTF8-2"))])
    assert R("UTF8-2").parse_all("a")


def test_246_forward_reference_is_not_a_real_definition():
    """A rule created only by being mentioned has no definition to clobber."""

    source = _source_module("bar = %x61")

    class R(Rule):
        pass

    R.create("foo = bar")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GrammarWarning)
        _apply_imports(R, [("bar", source("bar"))])


# A warning nobody looks at would not have caught either bug, so look at it.
_IMPORT_SWEEP = """
import pkgutil
import warnings
from importlib import import_module

import abnf.grammars
from abnf.parser import GrammarWarning

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    for _, name, _ in pkgutil.walk_packages(abnf.grammars.__path__):
        if name == "cors" or name.startswith("rfc"):
            import_module(f"{abnf.grammars.__name__}.{name}")

print("\\n".join(
    str(w.message) for w in caught if issubclass(w.category, GrammarWarning)
))
"""


def test_246_no_bundled_grammar_warns_on_import():
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _IMPORT_SWEEP],
        capture_output=True,
        text=True,
        check=True,
    )
    warned = [line for line in result.stdout.splitlines() if line]
    assert not warned, f"bundled grammars emit GrammarWarning on import: {warned}"


# Issue #257: RFC 5234 section 4 has `defined-as = *c-wsp ("=" / "=/") *c-wsp`,
# and c-wsp reaches `comment` through c-nl -- so a comment may sit on either
# side of the operator and is part of the defined-as span.  `visit_defined_as`
# returned that span stripped, which removes whitespace but not comment text,
# so the result compared unequal to "=" and fell into the "=/" branch.
def test_257_comment_before_equals_defines_a_new_rule():
    class R(Rule):
        pass

    R.load_grammar('bar ;note\r\n = "x"\r\n')
    assert R('bar').parse_all('x').value == 'x'


def test_257_comment_before_equals_is_still_a_redefinition():
    class R(Rule):
        pass

    R.load_grammar('foo = "x"\r\n')
    with pytest.warns(GrammarWarning, match="redefines 'foo'"):
        R.load_grammar('foo ;note\r\n = "y"\r\n')
    # '=' discards the earlier definition; '=/' would have kept it.
    assert R('foo').parse_all('y').value == 'y'
    with pytest.raises(ParseError):
        R('foo').parse_all('x')


def test_257_comment_containing_the_other_operator_is_not_the_operator():
    """Scanning the span for '=/' would misread this as an incremental rule."""

    class R(Rule):
        pass

    R.load_grammar('foo = "x"\r\n')
    with pytest.warns(GrammarWarning):
        R.load_grammar('foo ;see =/ below\r\n = "y"\r\n')
    with pytest.raises(ParseError):
        R('foo').parse_all('x')


def test_257_comment_after_the_operator_too():
    class R(Rule):
        pass

    R.load_grammar('baz =;note\r\n "x"\r\n')
    assert R('baz').parse_all('x').value == 'x'


def test_257_real_incremental_alternative_still_works():
    class R(Rule):
        pass

    R.load_grammar('q = "x"\r\nq =/ "y"\r\n')
    assert R('q').parse_all('x').value == 'x'
    assert R('q').parse_all('y').value == 'y'


def test_257_incremental_alternative_with_a_comment():
    class R(Rule):
        pass

    R.load_grammar('q = "x"\r\nq ;note\r\n =/ "y"\r\n')
    assert R('q').parse_all('x').value == 'x'
    assert R('q').parse_all('y').value == 'y'


# Issue #256: core rules live on the base Rule class so every grammar can
# reference them, and Rule.get falls back to that registry -- so
# Rule("DIGIT") and MyGrammar("DIGIT") were one object, and defining through
# it replaced the rule for every grammar in the process.  A grammar defining
# `DIGIT = %x30-39 / "_"` made rfc3339 accept `2_26` as a four-digit year.
CORE_NAMES = ['ALPHA', 'BIT', 'CHAR', 'CRLF', 'DIGIT', 'DQUOTE', 'HEXDIG', 'OCTET', 'SP', 'WSP']


@pytest.mark.parametrize('name', CORE_NAMES)
def test_256_a_grammar_cannot_define_a_core_rule(name: str):
    class R(Rule):
        pass

    with pytest.raises(GrammarError, match='core rule'):
        R.create(f'{name} = %x61')


@pytest.mark.parametrize('name', CORE_NAMES)
def test_256_nor_extend_one_with_an_incremental_alternative(name: str):
    """`=/` mutates the shared rule just as `=` does."""

    class R(Rule):
        pass

    with pytest.raises(GrammarError, match='core rule'):
        R.create(f'{name} =/ %x61')


@pytest.mark.parametrize('spelling', ['digit', 'Digit', 'DIGIT', 'dIgIt'])
def test_256_the_check_is_case_insensitive(spelling: str):
    """ABNF rule names are case-insensitive (RFC 5234 section 2.1)."""

    class R(Rule):
        pass

    with pytest.raises(GrammarError, match='core rule'):
        R.create(f'{spelling} = %x61')


def test_256_an_unrelated_grammar_is_not_corrupted():
    from abnf.grammars import rfc3339

    class R(Rule):
        pass

    with pytest.raises(GrammarError):
        R.create('DIGIT = %x30-39 / "_"')
    # date-fullyear is 4DIGIT; an underscore must not become a digit.
    with pytest.raises(ParseError):
        rfc3339.Rule('date-fullyear').parse_all('2_26')
    assert rfc3339.Rule('date-fullyear').parse_all('2026').value == '2026'


def test_256_ordinary_names_are_unaffected():
    """Only the base registry is protected; normal rules are per-subclass."""

    class G1(Rule):
        pass

    class G2(Rule):
        pass

    G1.create('token = %x61')
    G2.create('token = %x62')
    assert G1('token') is not G2('token')
    assert G1('token').parse_all('a').value == 'a'
    assert G2('token').parse_all('b').value == 'b'


def test_256_a_grammar_can_still_reference_core_rules():
    class R(Rule):
        pass

    R.create('pair = DIGIT ALPHA')
    assert R('pair').parse_all('1a').value == '1a'
    assert R('DIGIT') is Rule('DIGIT')


def test_256_the_message_says_what_to_do():
    class R(Rule):
        pass

    with pytest.raises(GrammarError) as excinfo:
        R.create('DIGIT = %x61')
    message = str(excinfo.value)
    assert 'delete this line' in message
    assert 'abnf.parser.Rule' in message
