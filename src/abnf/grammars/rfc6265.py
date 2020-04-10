"""
Collected rules from RFC 6265
https://tools.ietf.org/html/rfc6265
"""

from ..parser import Rule as _Rule
from . import rfc3986, rfc7230, rfc7231
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("token", rfc7230.Rule("token")),
        ("IPv4address", rfc3986.Rule("IPv4address")),
        ("IPv6address", rfc3986.Rule("IPv6address")),
        ("date1", rfc7231.Rule("date1")),
        ("wkday", rfc7231.Rule("day-name")),
        ("day", rfc7231.Rule("day")),
        ("month", rfc7231.Rule("month")),
        ("year", rfc7231.Rule("year")),
        ("time", rfc7231.Rule("time-of-day")),
        ("hour", rfc7231.Rule("hour")),
        ("minute", rfc7231.Rule("minute")),
        ("second", rfc7231.Rule("second")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 6265."""

    grammar = [
        "OWS = *( [ obs-fold ] WSP )",
        "obs-fold = CRLF",
        'set-cookie-header = "Set-Cookie:" SP set-cookie-string',
        'set-cookie-string = cookie-pair *( ";" SP cookie-av )',
        'cookie-pair = cookie-name "=" cookie-value',
        "cookie-name = token",
        "cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )",
        "cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E",
        # token = <token, defined in [RFC2616], Section 2.2>' -- the rule below is
        # constructed by hand from RFC 2616 definition.
        "token = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7A / %x7C",
        "cookie-av = expires-av / max-age-av / domain-av / path-av / secure-av / httponly-av / extension-av",
        'expires-av = "Expires=" sane-cookie-date',
        # sane-cookie-date = <rfc1123-date, defined in [RFC2616], Section 3.3.1>'
        # rfc1123-date is expressed in terms of rules imported from rfc7231
        "sane-cookie-date = rfc1123-date",
        'rfc1123-date = wkday "," SP date1 SP time SP "GMT"',
        'max-age-av = "Max-Age=" non-zero-digit *DIGIT',
        "non-zero-digit = %x31-39",
        'domain-av = "Domain=" domain-value',
        # domain-value = <subdomain>'
        # these next three rules are constructed following RFC 1034 and RFC 1123, with
        # IPv6 address support thrown in.
        'label = (ALPHA / DIGIT) *(((ALPHA / DIGIT / "-") (ALPHA / DIGIT)) / (ALPHA / DIGIT))',
        'subdomain = label *("." label)',
        "domain-value = subdomain / IPv4address / IPv6address",
        #
        'path-av = "Path=" path-value',
        "path-value = 1*(%x20-3A / %x3C-7E)",
        'secure-av = "Secure"',
        'httponly-av = "HttpOnly"',
        "extension-av = 1*( %x20-3A / %x3C-7E)",
        "cookie-date = *delimiter date-token-list *delimiter",
        "date-token-list = date-token *( 1*delimiter date-token )",
        "date-token = 1*non-delimiter",
        "delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E",
        'non-delimiter = %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF',
        "non-digit = %x00-2F / %x3A-FF",
        "day-of-month = 1*2DIGIT ( non-digit *OCTET )",
        'month = ( "jan" / "feb" / "mar" / "apr" / "may" / "jun" / "jul" / "aug" / "sep" / "oct" / "nov" / "dec" ) *OCTET',
        "year = 2*4DIGIT ( non-digit *OCTET )",
        "time = hms-time ( non-digit *OCTET )",
        'hms-time = time-field ":" time-field ":" time-field',
        "time-field = 1*2DIGIT",
        'cookie-header = "Cookie:" OWS cookie-string OWS',
        'cookie-string = cookie-pair *( ";" SP cookie-pair )',
    ]
