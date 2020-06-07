"""Miscellaneous functions."""


def load_grammar_rules(imported_rules=None):
    """A decorator that loads grammar rules following class declaration.  The code assumes
    that cls is a Rule subclass with a grammar attribute.
    The imported_rules parameter allows one to import rules from other modules. For examples,
    see for instance rfc7230.py.
    """

    def rule_decorator(cls):
        """The function returned by decorator."""
        for src in cls.grammar:
            cls.create(src)
        if imported_rules:
            for rule_def in imported_rules:
                cls(rule_def[0], rule_def[1].definition)
        return cls

    return rule_decorator
