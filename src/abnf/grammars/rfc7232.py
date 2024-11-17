"""
Collected rules from RFC 7232
https://tools.ietf.org/html/rfc7232

Note that this RFC is obsolete as of June 2022, replaced by 
https://www.rfc-editor.org/rfc/rfc9110.
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc7230, rfc7231
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("HTTP-date", rfc7231.Rule("HTTP-date")),
        ("OWS", rfc7230.Rule("OWS")),
        ("obs-text", rfc7230.Rule("obs-text")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7232."""

    grammar: ClassVar[Union[list[str], str]] = [
        "ETag = entity-tag",
        # HTTP-date = <HTTP-date, see [RFC7231], Section 7.1.1.1>
        'If-Match = "*" / ( *( "," OWS ) entity-tag *( OWS "," [ OWS entity-tag ] ) )',
        "If-Modified-Since = HTTP-date",
        'If-None-Match = "*" / ( *( "," OWS ) entity-tag *( OWS "," [ OWS entity-tag ] ) )',
        "If-Unmodified-Since = HTTP-date",
        "Last-Modified = HTTP-date",
        # OWS = <OWS, see [RFC7230], Section 3.2.3>
        "entity-tag = [ weak ] opaque-tag",
        'etagc = "!" / %x23-7E / obs-text',
        # obs-text = <obs-text, see [RFC7230], Section 3.2.6>
        "opaque-tag = DQUOTE *etagc DQUOTE",
        "weak = %x57.2F",
    ]
