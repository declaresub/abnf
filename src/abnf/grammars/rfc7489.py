"""
Collected rules from RFC 7489
https://tools.ietf.org/html/rfc7489
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc5322
from .misc import load_grammar_rules


@load_grammar_rules([("addr-spec", rfc5322.Rule("addr-spec"))])
class Rule(_Rule):
    """Rules from RFC 7489."""

    """grammar = [
        # This value is an integer in [0,100]
        # Originaly 'dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT'. 'pct=999' is following the grammar but is wrong.
        'dmarc-record = dmarc-version dmarc-sep dmarc-request *( dmarc-sep ( dmarc-srequest / dmarc-auri / dmarc-furi / dmarc-aspf / dmarc-adkim / dmarc-aspf dmarc-ainterval / dmarc-fo / dmarc-percent ) ) dmarc-sep'

    ]"""
    grammar: ClassVar[list[str] | str] = [
        # RFC 7489 defines URI as RFC 3986's, but section 6.2 supports only
        # the mailto scheme, so this narrows it deliberately.  Written as a
        # char-val rather than as %x6D %x61 ... so that it is
        # case-insensitive, as RFC 3986 section 3.1 requires of a scheme:
        # the %x form rejected "MAILTO:".
        'URI = "mailto:" addr-spec',
        'dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]',
        'dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31',
        "dmarc-sep = *WSP %x3b *WSP",
        'dmarc-request = "p" *WSP "=" *WSP ( "none" / "quarantine" / "reject" )',
        'dmarc-srequest  = "sp" *WSP "=" *WSP ( "none" / "quarantine" / "reject" )',
        'dmarc-auri = "rua" *WSP "=" *WSP dmarc-uri *(*WSP "," *WSP dmarc-uri)',
        'dmarc-furi  = "ruf" *WSP "=" *WSP dmarc-uri *(*WSP "," *WSP dmarc-uri)',
        'dmarc-adkim = "adkim" *WSP "=" *WSP ( "r" / "s" )',
        'dmarc-aspf = "aspf" *WSP "=" *WSP ( "r" / "s" )',
        'dmarc-ainterval = "ri" *WSP "=" *WSP 1*DIGIT',
        'dmarc-fo = "fo" *WSP "=" *WSP ( "0" / "1" / "d" / "s" ) *(*WSP ":" *WSP ( "0" / "1" / "d" / "s" ))',
        # Keyword for 'rf' in the rfc are only limited to afrf 'dmarc-rfmt = "rf"  *WSP "=" *WSP Keyword *(*WSP ":" Keyword)',
        'dmarc-rfmt = "rf"  *WSP "=" *WSP "afrf"',
        # Originaly 'dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT'. 'pct=999' is following the grammar but it is wrong
        'dmarc-percent = "pct" *WSP "=" *WSP ( "100" / 1*2DIGIT / "0" )',
        # RFC 7489 section 6.4 writes this as a fixed sequence of optional
        # components, then notes that "components other than dmarc-version
        # and dmarc-request may appear in any order" -- so a repetition of
        # alternatives is the reading that accepts what the prose allows.
        #
        # Both the request tag and the trailing separator are optional there,
        # and were required here: the record printed in RFC 7489 section
        # B.1.1 was rejected, as is any record without a trailing ";", which
        # is most of them in practice.  See
        # https://github.com/declaresub/abnf/issues/233 .
        "dmarc-tag = dmarc-request / dmarc-srequest / dmarc-auri / dmarc-furi "
        "/ dmarc-adkim / dmarc-aspf / dmarc-ainterval / dmarc-fo "
        "/ dmarc-percent / dmarc-rfmt",
        "dmarc-record = dmarc-version dmarc-sep [ dmarc-tag *(dmarc-sep dmarc-tag) ] [ dmarc-sep ]",
    ]
