"""
Collected rules from RFC 6266
https://tools.ietf.org/html/rfc6266
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc5987, rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("OWS", rfc7230.Rule("OWS")),
        ("ext-value", rfc5987.Rule("ext-value")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 6266."""

    # The grammar in this RFC follows the rules as defined in RFC 2616, not RFC 5234.  In particular, it
    # uses | instead of / for alternation, and white space here and there is implicit in RFC 2616.
    # The grammar below is updated to follow RFC 5234.

    grammar: ClassVar[Union[list[str], str]] = [
        'content-disposition = "Content-Disposition" ":" OWS disposition-type *(OWS  ";"  OWS disposition-parm )',
        'disposition-type    = "inline" / "attachment" / disp-ext-type',  # case-insensitive
        "disp-ext-type       = token",
        "disposition-parm    = filename-parm / disp-ext-parm",
        'filename-parm       = "filename" "=" value / "filename*" "=" ext-value',
        'disp-ext-parm       = token "=" value / ext-token "=" ext-value',
        'ext-token           = token "*"',  # <the characters in token, followed by "*">,'
        # this rule is taken from RFC 2616; it seems to have not made it into RFC 7230.
        "value = token / quoted-string",
    ]
