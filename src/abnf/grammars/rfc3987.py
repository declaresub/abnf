from abnf.parser import Rule as _Rule

from . import rfc3986
from .misc import load_grammar_rulelist


@load_grammar_rulelist(
    [
        ("scheme", rfc3986.Rule("scheme")),
        ("port", rfc3986.Rule("port")),
        ("IP-literal", rfc3986.Rule("IP-literal")),
        ("IPvFuture", rfc3986.Rule("IPvFuture")),
        ("IPv6address", rfc3986.Rule("IPv6address")),
        ("h16", rfc3986.Rule("h16")),
        ("ls32", rfc3986.Rule("ls32")),
        ("IPv4address", rfc3986.Rule("IPv4address")),
        ("dec-octet", rfc3986.Rule("dec-octet")),
        ("pct-encoded", rfc3986.Rule("pct-encoded")),
        ("unreserved", rfc3986.Rule("unreserved")),
        ("reserved", rfc3986.Rule("reserved")),
        ("gen-delims", rfc3986.Rule("gen-delims")),
        ("sub-delims", rfc3986.Rule("sub-delims")),
    ]
)
class Rule(_Rule):
    """Grammar from RFC 3987."""

    grammar = """
IRI            = scheme ":" ihier-part [ "?" iquery ]
                    [ "#" ifragment ]

ihier-part     = "//" iauthority ipath-abempty
                / ipath-absolute
                / ipath-rootless
                / ipath-empty

IRI-reference  = IRI / irelative-ref

absolute-IRI   = scheme ":" ihier-part [ "?" iquery ]

irelative-ref  = irelative-part [ "?" iquery ] [ "#" ifragment ]

irelative-part = "//" iauthority ipath-abempty
                / ipath-absolute
                / ipath-noscheme
                / ipath-empty

iauthority     = [ iuserinfo "@" ] ihost [ ":" port ]
iuserinfo      = *( iunreserved / pct-encoded / sub-delims / ":" )
ihost          = IP-literal / IPv4address / ireg-name

ireg-name      = *( iunreserved / pct-encoded / sub-delims )

ipath          = ipath-abempty   ; begins with "/" or is empty
                / ipath-absolute  ; begins with "/" but not "//"
                / ipath-noscheme  ; begins with a non-colon segment
                / ipath-rootless  ; begins with a segment
                / ipath-empty     ; zero characters

ipath-abempty  = *( "/" isegment )
ipath-absolute = "/" [ isegment-nz *( "/" isegment ) ]
ipath-noscheme = isegment-nz-nc *( "/" isegment )
ipath-rootless = isegment-nz *( "/" isegment )
ipath-empty    = 0<ipchar>

isegment       = *ipchar
isegment-nz    = 1*ipchar
isegment-nz-nc = 1*( iunreserved / pct-encoded / sub-delims
                    / "@" )
                ; non-zero-length segment without any colon ":"

ipchar         = iunreserved / pct-encoded / sub-delims / ":"
                / "@"

iquery         = *( ipchar / iprivate / "/" / "?" )

ifragment      = *( ipchar / "/" / "?" )

iunreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~" / ucschar

ucschar        = %xA0-D7FF / %xF900-FDCF / %xFDF0-FFEF
                / %x10000-1FFFD / %x20000-2FFFD / %x30000-3FFFD
                / %x40000-4FFFD / %x50000-5FFFD / %x60000-6FFFD
                / %x70000-7FFFD / %x80000-8FFFD / %x90000-9FFFD
                / %xA0000-AFFFD / %xB0000-BFFFD / %xC0000-CFFFD
                / %xD0000-DFFFD / %xE1000-EFFFD

iprivate       = %xE000-F8FF / %xF0000-FFFFD / %x100000-10FFFD
    """


# ßee https://www.rfc-editor.org/rfc/rfc3987#section-2.2
for rule in Rule.rules():
    rule.first_match_alternation = True
