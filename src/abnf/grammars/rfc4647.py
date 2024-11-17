"""
Collected rules from RFC 4647
https://tools.ietf.org/html/rfc4647
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rule objects generated from ABNF in RFC 4647."""

    grammar: ClassVar[Union[list[str], str]] = [
        'language-range = (1*8ALPHA *("-" 1*8alphanum)) / "*"',
        "alphanum = ALPHA / DIGIT",
        'extended-language-range = (1*8ALPHA / "*") *("-" (1*8alphanum / "*"))',
    ]
