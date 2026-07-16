"""
Collected rules from RFC 7838
https://tools.ietf.org/html/rfc7838
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
        ("uri-host", rfc7230.Rule("uri-host")),
        ("port", rfc7230.Rule("port")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7838.

    Note: RFC 7838 Section 3.1 requires that the ALPN protocol name in
    ``protocol-id`` be percent-encoded for any octet that is not a valid
    ``token`` character, using uppercase hexadecimal digits. That constraint
    applies to the *content* of the name and is not expressible in ABNF, so
    ``protocol-id`` is defined here simply as ``token``, matching the RFC's
    own grammar.
    """

    grammar: ClassVar[list[str] | str] = [
        # Alt-Svc = clear / 1#alt-value ; 1#element expanded per RFC 7230 Section 7
        'Alt-Svc       = clear / ( *( "," OWS ) alt-value *( OWS "," [ OWS alt-value ] ) )',
        'clear         = %s"clear"',
        'alt-value     = alternative *( OWS ";" OWS parameter )',
        'alternative   = protocol-id "=" alt-authority',
        "protocol-id   = token",
        "alt-authority = quoted-string",
        'parameter     = token "=" ( token / quoted-string )',
        'Alt-Used      = uri-host [ ":" port ]',
        # OWS           = <OWS, see [RFC7230], Section 3.2.3>
        # token         = <token, see [RFC7230], Section 3.2.6>
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>
        # uri-host      = <uri-host, see [RFC7230], Section 2.7>
        # port          = <port, see [RFC7230], Section 2.7>
    ]
