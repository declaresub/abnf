"""
Collected rules from RFC 3986, Appendix A.
https://tools.ietf.org/html/rfc3986#appendix-A
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rules from RFC 3986."""

    grammar: ClassVar[list[str] | str] = [
        'URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]',
        'hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty',
        "URI-reference = URI / relative-ref",
        'absolute-URI = scheme ":" hier-part [ "?" query ]',
        'relative-ref = relative-part [ "?" query ] [ "#" fragment ]',
        'relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty',
        'scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )',
        'authority = [ userinfo "@" ] host [ ":" port ]',
        'userinfo = *( unreserved / pct-encoded / sub-delims / ":" )',
        "host = IP-literal / IPv4address / reg-name",
        "port = *DIGIT",
        'IP-literal = "[" ( IPv6address / IPvFuture ) "]"',
        'IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )',
        'IPv6address = 6( h16 ":" ) ls32 / "::" 5( h16 ":" ) ls32 / [ h16 ] "::" 4( h16 ":" ) ls32 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32 / [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32 / [ *4( h16 ":" ) h16 ] "::" ls32 / [ *5( h16 ":" ) h16 ] "::" h16 / [ *6( h16 ":" ) h16 ] "::"',
        "h16 = 1*4HEXDIG",
        'ls32 = ( h16 ":" h16 ) / IPv4address',
        'IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet',
        # alternatives reordered for correct matching.
        'dec-octet = "25" %x30-35 / "2" %x30-34 DIGIT / "1" 2DIGIT / %x31-39 DIGIT / DIGIT',
        "reg-name = *( unreserved / pct-encoded / sub-delims )",
        "path = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty",
        'path-abempty = *( "/" segment )',
        'path-absolute = "/" [ segment-nz *( "/" segment ) ]',
        'path-noscheme = segment-nz-nc *( "/" segment )',
        'path-rootless = segment-nz *( "/" segment )',
        "path-empty = 0pchar",
        "segment = *pchar",
        "segment-nz = 1*pchar",
        'segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )',
        'pchar = unreserved / pct-encoded / sub-delims / ":" / "@"',
        'query = *( pchar / "/" / "?" )',
        'fragment = *( pchar / "/" / "?" )',
        'pct-encoded = "%" HEXDIG HEXDIG',
        'unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"',
        "reserved = gen-delims / sub-delims",
        'gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"',
        'sub-delims = "!" / "$" / "&" / "\'" / "(" / ")" / "*" / "+" / "," / ";" / "="',
    ]


# RFC 3986 section 3.2.2 says that a host matching IPv4address "should be
# considered an IPv4 address literal and not a reg-name".  That is a rule
# about attributing a match of the whole host, and longest-match alternation
# already satisfies it: a full IPv4 host ties with reg-name, and the tie is
# broken by declaration order, which puts IPv4address first.
#
# `host` used to set `first_match_alternation`, citing that section.  Under
# first match the alternation commits to IPv4address on a *prefix*: given
# `1.2.3.4.5`, IPv4address matched `1.2.3.4`, reg-name was never tried, and
# the whole URI was rejected -- as was any host of the shape
# `1.2.3.4.in-addr.arpa`.  See https://github.com/declaresub/abnf/issues/232 .
