"""
Collected rules from RFC 7489
https://tools.ietf.org/html/rfc7489
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc5322
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("addr-spec", rfc5322.Rule("addr-spec"))
    ]
)



class Rule(_Rule):
    """Rules from RFC 7489."""

    '''grammar = [
        # This value is an integer in [0,100]
        # Originaly 'dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT'. 'pct=999' is following the grammar but is wrong.
        'dmarc-record = dmarc-version dmarc-sep dmarc-request *( dmarc-sep ( dmarc-srequest / dmarc-auri / dmarc-furi / dmarc-aspf / dmarc-adkim / dmarc-aspf dmarc-ainterval / dmarc-fo / dmarc-percent ) ) dmarc-sep'

    ]'''
    grammar: ClassVar[Union[list[str], str]] = [
            'URI = %x6D %x61 %x69 %x6C %x74 %x6F %x3A addr-spec',
            'dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]',
            
            'dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31',
            'dmarc-sep = *WSP %x3b *WSP',
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
            'dmarc-record = dmarc-version dmarc-sep dmarc-request *(dmarc-sep (dmarc-srequest / dmarc-auri / dmarc-furi / dmarc-aspf / dmarc-adkim / dmarc-aspf / dmarc-ainterval / dmarc-fo / dmarc-percent / dmarc-rfmt)) dmarc-sep'
        ]
