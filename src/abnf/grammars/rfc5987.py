"""
Collected rules from RFC 5987
https://tools.ietf.org/html/rfc5987
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc5646, rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
    ("quoted-string", rfc7230.Rule("quoted-string")),
    ("token", rfc7230.Rule("token")),
    ("language", rfc5646.Rule("language-tag")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 5987."""

    grammar: ClassVar[Union[list[str], str]] = [
    #'#parameter     = attribute LWSP "=" LWSP value',
    #'attribute     = token',
    'value         = token / quoted-string',

    #quoted-string = <quoted-string, defined in [RFC2616], Section 2.2>
    #token         = <token, defined in [RFC2616], Section 2.2>

    # In order to include character set and language information, this
    # specification modifies the RFC 2616 grammar to be:

    'parameter     = reg-parameter / ext-parameter',

    'reg-parameter = parmname LWSP "=" LWSP value',

    'ext-parameter = parmname "*" LWSP "=" LWSP ext-value',

    'parmname      = 1*attr-char',

    'ext-value     = charset  "\'" [ language ] "\'" value-chars',
                   # like RFC 2231's <extended-initial-value>
                   # (see [RFC2231], Section 7)

    'charset       = "UTF-8" / "ISO-8859-1" / mime-charset',

    'mime-charset  = 1*mime-charsetc',
    'mime-charsetc = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "+" / "-" / "^" / "_" / "`" / "{" / "}" / "~"',
                   # as <mime-charset> in Section 2.3 of [RFC2978]
                   # except that the single quote is not included
                   # SHOULD be registered in the IANA charset registry

     #language      = <Language-Tag, defined in [RFC5646], Section 2.1>

    'value-chars   = *( pct-encoded / attr-char )',

    'pct-encoded   = "%" HEXDIG HEXDIG',
                   # see [RFC3986], Section 2.1

    'attr-char     = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"',
                   # token except ( "*" / "'" / "%" )
    ]
