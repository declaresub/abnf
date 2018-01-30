"""
Collected rules from RFC 8287
https://tools.ietf.org/html/rfc8287
"""

from ..parser import Rule as _Rule
from . import rfc7230
from .misc import load_grammar_rules



@load_grammar_rules([])
class Rule(_Rule):
    """Rules from RFC 8287."""

    grammar = [
    ]
