"""
Collected rules from RFC 7234
https://tools.ietf.org/html/rfc7234
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc7230, rfc7231
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("OWS", rfc7230.Rule("OWS")),
        ("field-name", rfc7230.Rule("field-name")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("token", rfc7230.Rule("token")),
        ("port", rfc7230.Rule("port")),
        ("pseudonym", rfc7230.Rule("pseudonym")),
        ("uri-host", rfc7230.Rule("uri-host")),
        ("HTTP-date", rfc7231.Rule("HTTP-date")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7234."""

    grammar: ClassVar[Union[list[str], str]] = [
        "Age = delta-seconds",
        'Cache-Control = *( "," OWS ) cache-directive *( OWS "," [ OWS cache-directive ] )',
        "Expires = HTTP-date",
        # HTTP-date = <HTTP-date, see [RFC7231], Section 7.1.1.1>,
        # OWS = <OWS, see [RFC7230], Section 3.2.3>
        'Pragma = *( "," OWS ) pragma-directive *( OWS "," [ OWS pragma-directive ] )',
        'Warning = *( "," OWS ) warning-value *( OWS "," [ OWS warning-value ] )',
        'cache-directive = token [ "=" ( token / quoted-string ) ]',
        "delta-seconds = 1*DIGIT",
        'extension-pragma = token [ "=" ( token / quoted-string ) ]',
        # field-name = <field-name, see [RFC7230], Section 3.2>
        # port = <port, see [RFC7230], Section 2.7>
        'pragma-directive = "no-cache" / extension-pragma',
        # pseudonym = <pseudonym, see [RFC7230], Section 5.7.1>
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>
        # token = <token, see [RFC7230], Section 3.2.6>
        # uri-host = <uri-host, see [RFC7230], Section 2.7>
        'warn-agent = ( uri-host [ ":" port ] ) / pseudonym',
        "warn-code = 3DIGIT",
        "warn-date = DQUOTE HTTP-date DQUOTE",
        "warn-text = quoted-string",
        "warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]",
    ]
