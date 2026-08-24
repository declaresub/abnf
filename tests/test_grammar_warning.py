import subprocess
import sys
import warnings

import pytest

from abnf.grammars.misc import _apply_imports
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
