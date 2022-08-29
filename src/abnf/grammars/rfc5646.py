"""
Collected rules from RFC 5646
https://tools.ietf.org/html/rfc5646
"""

from abnf.parser import Rule as _Rule
from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rules from RFC 5646."""

    grammar = [
        "Language-Tag = langtag / privateuse / grandfathered",
        'langtag = language ["-" script] ["-" region] *("-" variant) *("-" extension) ["-" privateuse]',
        'language = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA',
        'extlang = 3ALPHA *2("-" 3ALPHA)',
        "script = 4ALPHA",
        "region = 2ALPHA / 3DIGIT",
        "variant = 5*8alphanum / (DIGIT 3alphanum)",
        'extension = singleton 1*("-" (2*8alphanum))',
        "singleton = DIGIT / %x41-57 / %x59-5A / %x61-77 / %x79-7A",
        'privateuse = "x" 1*("-" (1*8alphanum))',
        "grandfathered = irregular / regular",
        'irregular = "en-GB-oed" / "i-ami" / "i-bnn" / "i-default" / "i-enochian" / "i-hak" / "i-klingon" / "i-lux" / "i-mingo" / "i-navajo" / "i-pwn" / "i-tao" / "i-tay" / "i-tsu" / "sgn-BE-FR" / "sgn-BE-NL" / "sgn-CH-DE"',
        'regular = "art-lojban" / "cel-gaulish" / "no-bok" / "no-nyn" / "zh-guoyu" / "zh-hakka" / "zh-min" / "zh-min-nan" / "zh-xiang"',
        "alphanum = (ALPHA / DIGIT)",
    ]
