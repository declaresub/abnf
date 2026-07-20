"""
Collected rules from RFC 8288
https://tools.ietf.org/html/rfc8288
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc3986, rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("OWS", rfc7230.Rule("OWS")),
        ("BWS", rfc7230.Rule("BWS")),
        ("URI-Reference", rfc3986.Rule("URI-reference")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 8288."""

    # RFC 8288 defines Link using the "#rule" list extension from RFC 7230,
    # Section 7.  That extension is not part of RFC 5234 ABNF, so Link is
    # expanded here to its equivalent RFC 5234 form:
    #     Link = #link-value
    #          = [ link-value *( OWS "," OWS link-value ) ]
    grammar: ClassVar[list[str] | str] = [
        'Link       = [ link-value *( OWS "," OWS link-value ) ]',
        'link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )',
        'link-param = token BWS [ "=" BWS ( token / quoted-string ) ]',
        # token         = <token, see [RFC7230], Section 3.2.6>
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>
        # OWS           = <OWS, see [RFC7230], Section 3.2.3>
        # BWS           = <BWS, see [RFC7230], Section 3.2.3>
        # URI-Reference = <URI-reference, see [RFC3986], Section 4.1>
    ]
