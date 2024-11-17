"""Miscellaneous functions."""

from typing import Optional

from abnf.parser import ABNFGrammarNodeVisitor, ABNFGrammarRule, Rule

__all__ = ['load_grammar_rules', 'load_grammar_rulelist']

def load_grammar_rules(imported_rules: Optional[list[tuple[str, Rule]]] = None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: type[Rule]):
        """The function returned by decorator."""

        if isinstance(cls.grammar, str):
            msg = 'This decorator must be used with a grammar of type list'
            raise TypeError(msg)

        for src in cls.grammar:
            cls.create(src)
        if imported_rules:
            for rule_def in imported_rules:
                cls(rule_def[0], rule_def[1].definition)
        return cls

    return rule_decorator


def load_grammar_rulelist(imported_rules: Optional[list[tuple[str, Rule]]] = None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: type[Rule]):
        """The function returned by decorator."""
        assert isinstance(cls.grammar, str)
        src = cls.grammar.rstrip().replace("\r", "").replace("\n", "\r\n") + '\r\n'
        node = ABNFGrammarRule("rulelist").parse_all(src)
        visitor = ABNFGrammarNodeVisitor(cls)
        visitor.visit(node)

        if imported_rules:
            for rule_def in imported_rules:
                cls(rule_def[0], rule_def[1].definition)
        return cls

    return rule_decorator
