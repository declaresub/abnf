"""
This is the extension to RFC 5234 which adds case-sensitive char-val.

Collected rules from RFC 5322
https://tools.ietf.org/html/rfc5322
"""

from ..parser import Rule as _Rule
from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rule objects generated from ABNF in RFC 5322."""

    grammar = [
        "char-val = case-insensitive-string /\
                           case-sensitive-string",
        'case-insensitive-string =\
                           [ "%i" ] quoted-string',
        'case-sensitive-string =\
                           "%s" quoted-string',
        "quoted-string  =  DQUOTE *(%x20-21 / %x23-7E) DQUOTE\
                                ; quoted string of SP and VCHAR\
                                ;  without DQUOTE",
    ]
