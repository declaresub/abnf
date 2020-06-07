"""
Collected rules from RFC 7235
https://tools.ietf.org/html/rfc7235
"""

from ..parser import Rule as _Rule
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

    grammar = [
        "Authorization = credentials",
        # BWS = <BWS, see [RFC7230], Section 3.2.3>',
        # OWS = <OWS, see [RFC7230], Section 3.2.3>',
        # See discussion below for WWW-Authenticate.
        #'Proxy-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge ] )',
        'Proxy-Authenticate = *( "," OWS ) challenge *( OWS ("," / challenge) )',
        "Proxy-Authorization = credentials",
        # The rule WWW-Authenticate is ambiguous. I am not the first person to observe this
        # <https://www.ietf.org/mail-archive/web/httpbisa/current/msg07914.html>.
        # The problem is essentially nested comma-separated lists.  Using the rules given
        # in RFC 7235 with this parser, parsing source 'Basic realm="foo", Pascal realm="bar"
        # using the rule WWW-Authenticate will result in the consumption of 'Basic realm="foo",'.
        # So we tinker a bit to account for the challenge rule consuming the trailing comma.
        #'WWW-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge ] )',
        'WWW-Authenticate = *( "," OWS ) challenge *( OWS ("," / challenge) )',
        'auth-param = token BWS "=" BWS ( token / quoted-string )',
        "auth-scheme = token",
        'challenge = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param ) *(OWS "," [ OWS auth-param ] ) ] ) ]',
        'credentials = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param ) *( OWS "," [ OWS auth-param ] ) ] ) ]',
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>',
        # token = <token, see [RFC7230], Section 3.2.6>',
        'token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="',
    ]
