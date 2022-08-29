"""
Collected rules from RFC 3629, Appendix A.
https://datatracker.ietf.org/doc/html/rfc3629
"""

from abnf.parser import Rule as _Rule
from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rules from RFC 3629."""

    grammar = [
        'UTF8-octets = *( UTF8-char )',
        'UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4',
        'UTF8-1      = %x00-7F',
        'UTF8-2      = %xC2-DF UTF8-tail',
        'UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /\
                        %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )',
        'UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /\
                        %xF4 %x80-8F 2( UTF8-tail )',
        'UTF8-tail   = %x80-BF',
        ]
