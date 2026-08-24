"""
Collected rules from RFC 7235
https://tools.ietf.org/html/rfc7235

Note that this RFC is obsolete as of June 2022, replaced by
https://www.rfc-editor.org/rfc/rfc9110.
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("BWS", rfc7230.Rule("BWS")),
        ("OWS", rfc7230.Rule("OWS")),
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7235."""

    grammar: ClassVar[list[str] | str] = [
        "Authorization = credentials",
        # BWS = <BWS, see [RFC7230], Section 3.2.3>',
        # OWS = <OWS, see [RFC7230], Section 3.2.3>',
        # Both of these carried a workaround for the ambiguity in RFC 7235's
        # own expansion: `challenge` can consume a trailing comma, so
        # `Basic realm="foo", Pascal realm="bar"` used to parse only as far as
        # the comma.  9c4ab8f (2022) found the parser had grown enough
        # backtracking to handle the rule as written and reverted
        # WWW-Authenticate to it -- but left Proxy-Authenticate on the
        # workaround, so two rules the RFC defines identically accepted
        # different languages, and the comma-less
        # `Basic realm="a" Newauth realm="b"` was accepted here.
        # See https://github.com/declaresub/abnf/issues/237 .
        'Proxy-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge ] )',
        "Proxy-Authorization = credentials",
        'WWW-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge ] )',
        'auth-param = token BWS "=" BWS ( token / quoted-string )',
        "auth-scheme = token",
        'challenge = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param ) *(OWS "," [ OWS auth-param ] ) ] ) ]',
        'credentials = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param ) *( OWS "," [ OWS auth-param ] ) ] ) ]',
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>',
        # token = <token, see [RFC7230], Section 3.2.6>',
        'token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="',
    ]
