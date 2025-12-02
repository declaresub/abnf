"""
Collected rules from RFC 7239
https://tools.ietf.org/html/rfc7239
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("OWS", rfc7230.Rule("OWS")),
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7239."""

    grammar: ClassVar[list[str] | str] = [
        'Forwarded         = forwarded-element *( OWS "," OWS forwarded-element )',
        'forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )',
        'forwarded-pair    = token "=" value',
        'value             = token / quoted-string',
        # OWS              = <OWS, see [RFC7230], Section 3.2.3>',
        # token            = <token, see [RFC7230], Section 3.2.6>',
        # quoted-string    = <quoted-string, see [RFC7230], Section 3.2.6>',
    ]
