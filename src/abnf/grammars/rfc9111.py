"""
Collected rules from RFC 9111
https://www.rfc-editor.org/rfc/rfc9111.html
"""

from abnf.parser import Rule as _Rule

from . import rfc9110
from .misc import load_grammar_rulelist


@load_grammar_rulelist(
    [
        ("HTTP-date", rfc9110.Rule("HTTP-date")),
        ("OWS", rfc9110.Rule("OWS")),
        ("field-name", rfc9110.Rule("field-name")),
        ("quoted-string", rfc9110.Rule("quoted-string")),
        ("token", rfc9110.Rule("token")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 9111."""

    grammar = r"""
Age = delta-seconds

Cache-Control = [ cache-directive *( OWS "," OWS cache-directive ) ]

Expires = HTTP-date

HTTP-date = <HTTP-date, see [HTTP], Section 5.6.7>

OWS = <OWS, see [HTTP], Section 5.6.3>

cache-directive = token [ "=" ( token / quoted-string ) ]

delta-seconds = 1*DIGIT

field-name = <field-name, see [HTTP], Section 5.1>

quoted-string = <quoted-string, see [HTTP], Section 5.6.4>

token = <token, see [HTTP], Section 5.6.2>
"""
