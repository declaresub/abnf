"""
Collected rules from RFC 7240
https://tools.ietf.org/html/rfc7240
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
        ("BWS", rfc7230.Rule("BWS")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7240."""

    grammar: ClassVar[list[str] | str] = [
        # 1#preference expanded per RFC 7230, Section 7.
        'Prefer = "Prefer" ":" OWS preference *( OWS "," OWS preference )',
        'preference = token [ BWS "=" BWS word ] *( OWS ";" [ OWS parameter ] )',
        'parameter = token [ BWS "=" BWS word ]',
        "word = token / quoted-string",
        # RFC 7240 section 3 defines this over `applied-pref`, not
        # `preference`: "The syntax of the Preference-Applied header differs
        # from that of the Prefer header in that parameters are not
        # included."  Building it from `preference` accepted
        # `Preference-Applied: respond-async; wait=10`, which the RFC does
        # not.  1#applied-pref expanded as above.  See
        # https://github.com/declaresub/abnf/issues/237 .
        'Preference-Applied = "Preference-Applied" ":" OWS applied-pref *( OWS "," OWS applied-pref )',
        'applied-pref = token [ BWS "=" BWS word ]',
        # OWS           = <OWS, see [RFC7230], Section 3.2.3>
        # BWS           = <BWS, see [RFC7230], Section 3.2.3>
        # token         = <token, see [RFC7230], Section 3.2.6>
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>
    ]
