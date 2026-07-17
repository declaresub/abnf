"""
Collected rules from RFC 6797
https://www.rfc-editor.org/rfc/rfc6797.html
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("OWS", rfc7230.Rule("OWS")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 6797.

    RFC 6797, Section 6.1 defines token and quoted-string by reference to
    RFC 2616, Section 2.2; the functionally equivalent RFC 7230 definitions
    are used here.  Per RFC 2616's implied *LWS rule, OWS is inserted around
    the ":" and ";" delimiters so that header field values such as
    'max-age=31536000; includeSubDomains' parse.  The "|" of the RFC 6797
    directive-value rule is written as "/" per RFC 5234.
    """

    grammar: ClassVar[list[str] | str] = [
        'Strict-Transport-Security = "Strict-Transport-Security" ":" OWS '
        '[ directive ] *( OWS ";" OWS [ directive ] )',
        'directive = directive-name [ "=" directive-value ]',
        "directive-name = token",
        "directive-value = token / quoted-string",
        # token         = <token, see [RFC2616], Section 2.2>
        # quoted-string = <quoted-string, see [RFC2616], Section 2.2>
        # OWS           = <OWS, see [RFC7230], Section 3.2.3>
    ]
