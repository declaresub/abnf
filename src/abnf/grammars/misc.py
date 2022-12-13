"""Miscellaneous functions."""

from typing import List, Optional, Tuple, Type
from abnf.parser import Rule

def load_grammar_rules(imported_rules: Optional[List[Tuple[str, Rule]]]=None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: Type[Rule]):
        """The function returned by decorator."""

        if isinstance(cls.grammar, str):
            raise TypeError('This decorator must be used with a grammar of tyoe list')

        for src in cls.grammar:
            cls.create(src)
        if imported_rules:
            for rule_def in imported_rules:
                cls(rule_def[0], rule_def[1].definition)
        return cls

    return rule_decorator


def load_grammar(imported_rules: Optional[List[Tuple[str, Rule]]]=None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls: Type[Rule]):
        """The function returned by decorator."""
        if isinstance(cls.grammar, list):
            raise TypeError('This decorator must be used with a grammar of tyoe str.')
        cls.load_grammar(cls.grammar)
        if imported_rules:
            for rule_def in imported_rules:
                cls(rule_def[0], rule_def[1].definition)
        return cls

    return rule_decorator
