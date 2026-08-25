"""Miscellaneous functions."""

import warnings

from abnf.parser import (
    ABNFGrammarNodeVisitor,
    ABNFGrammarRule,
    GrammarWarning,
    Prose,
    Rule,
)

__all__ = ["load_grammar_rulelist", "load_grammar_rules"]


def _apply_imports(cls: type[Rule], imported_rules: list[tuple[str, Rule]]) -> None:
    """Apply an import list to ``cls``, warning about accidental overwrites.

    Imports are applied after the grammar text, so an imported rule replaces a
    definition of the same name.  That is the intended mechanism: a module
    writes a rule it does not own as prose --
    ``token = <token, see [HTTP], Section 5.6.2>`` -- and lets the import
    supply the real one.  Replacing anything *other* than prose is an accident,
    and a silent one: it swaps a working definition for a different grammar's
    without a word.  See https://github.com/declaresub/abnf/issues/246 .

    Only the top-level definition is examined, because the rust backend's
    combinators expose no children to walk.  Every import collision in the
    bundled grammars is prose exactly at the top level, so that is enough.
    """

    #: Recorded for tooling that needs a module's effective grammar as text --
    #: see tests/fuzz/gen_abnfgen_corpus.py.  The decorator would otherwise
    #: discard the list, and it cannot be recovered from the loaded rules,
    #: whose definitions carry no record of where they came from.
    cls._imported_rules = tuple(imported_rules)

    for name, source in imported_rules:
        existing = cls._obj_map.get((cls, name.casefold()))
        definition = getattr(existing, "_definition", None)
        if definition is not None and not isinstance(definition, Prose):
            origin = type(source).__module__.rsplit(".", 1)[-1]
            msg = (
                f'importing "{name}" from {origin} overwrites the definition '
                f"{cls.__module__.rsplit('.', 1)[-1]} declares for it.  An "
                "import is meant to fill in a rule written as prose; this one "
                "replaces real grammar, which is how issue #234 was "
                "introduced."
            )
            warnings.warn(msg, GrammarWarning, stacklevel=3)
        cls(name, source.definition)


def load_grammar_rules(imported_rules: list[tuple[str, Rule]] | None = None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: type[Rule]):
        """The function returned by decorator."""

        if isinstance(cls.grammar, str):
            msg = "This decorator must be used with a grammar of type list"
            raise TypeError(msg)

        for src in cls.grammar:
            cls.create(src)
        if imported_rules:
            _apply_imports(cls, imported_rules)
        return cls

    return rule_decorator


def load_grammar_rulelist(imported_rules: list[tuple[str, Rule]] | None = None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: type[Rule]):
        """The function returned by decorator."""
        assert isinstance(cls.grammar, str)
        src = cls.grammar.rstrip().replace("\r", "").replace("\n", "\r\n") + "\r\n"
        node = ABNFGrammarRule("rulelist").parse_all(src)
        visitor = ABNFGrammarNodeVisitor(cls)
        visitor.visit(node)

        if imported_rules:
            _apply_imports(cls, imported_rules)
        return cls

    return rule_decorator
