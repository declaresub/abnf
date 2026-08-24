"""
This is the extension to RFC 5234 which adds case-sensitive char-val.

Collected rules from RFC 7405
https://tools.ietf.org/html/rfc7405
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc5234
from .misc import load_grammar_rules

#: Rules whose definitions reach `char-val`, directly or through the
#: mutual recursion between `element`, `group`, `option` and
#: `alternation`.  RFC 7405 exists to redefine `char-val`, and a rule
#: imported from `rfc5234` refers to *that* module's rule objects -- so
#: importing any of these would reach RFC 5234's plain `char-val` and
#: the extension would apply to nothing above it.  They are defined
#: below instead, copied from RFC 5234 unchanged.
#:
#: These names never reached the import list in practice -- the
#: comprehension below is evaluated while `rfc5234` is still being
#: populated, so it sees only the eleven leaf rules.  Naming them makes
#: the filter say what it means rather than depend on that timing.
#: See https://github.com/declaresub/abnf/issues/244 .
_REDEFINED = frozenset(
    {
        "char-val",
        "element",
        "repetition",
        "concatenation",
        "alternation",
        "elements",
        "group",
        "option",
        "rule",
        "rulelist",
    }
)


@load_grammar_rules(
    [
        (rule.name, rule)
        for rule in rfc5234.Rule.rules()
        if rule.name not in {core_rule.name for core_rule in _Rule.rules()}
        and rule.name not in _REDEFINED
    ]
)
class Rule(_Rule):
    """Rule objects generated from ABNF in RFC 7405."""

    grammar: ClassVar[list[str] | str] = [
        "char-val = case-insensitive-string /\
                           case-sensitive-string",
        'case-insensitive-string =\
                           [ "%i" ] quoted-string',
        'case-sensitive-string =\
                           "%s" quoted-string',
        "quoted-string  =  DQUOTE *(%x20-21 / %x23-7E) DQUOTE\
                                ; quoted string of SP and VCHAR\
                                ;  without DQUOTE",
        # Copied unchanged from RFC 5234, section 4, so that they resolve
        # `char-val` to the extended rule above rather than to RFC 5234's.
        "element = rulename / group / option / char-val / num-val / prose-val",
        "repetition = [repeat] element",
        "concatenation = repetition *(1*c-wsp repetition)",
        'alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)',
        "elements = alternation *c-wsp",
        'group = "(" *c-wsp alternation *c-wsp ")"',
        'option = "[" *c-wsp alternation *c-wsp "]"',
        "rule = rulename defined-as elements c-nl",
        "rulelist = 1*( rule / (*c-wsp c-nl) )",
    ]
