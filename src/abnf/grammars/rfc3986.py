"""
Collected rules from RFC 3986, Appendix A.
https://tools.ietf.org/html/rfc3986#appendix-A
"""

from abnf.parser import Rule as _Rule
from .misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rules from RFC 3986."""

    grammar = [
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
