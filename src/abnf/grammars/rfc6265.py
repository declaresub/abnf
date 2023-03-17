"""
Collected rules from RFC 6265
https://tools.ietf.org/html/rfc6265
"""

from abnf.parser import Rule as _Rule

from . import rfc2616, rfc3986
from .misc import load_grammar_rulelist


@load_grammar_rulelist(
    [
        ("IPv4address", rfc3986.Rule("IPv4address")),
        ("IPv6address", rfc3986.Rule("IPv6address")),
    ]
)
class LocalRule(_Rule):
    """
    Implementations of some RFC 6265 rules defined as prose values.
    The definition of subdomain is taken from RFC1034 and RFC1123, with IPv6 support
    added. The definition of subdomain found therein contained left-recursion; the definition
    here does not.
    The definitions of path-value, extension-av incorporate verified errata.
    """

    grammar = """
subdomain = label 0*("." label)
;subdomain = label / subdomain "." label
label = letter [ [ ldh-str ] let-dig ]
ldh-str = let-dig-hyp / let-dig-hyp ldh-str
let-dig-hyp = let-dig / "-"
letter = ALPHA
let-dig = letter / DIGIT

domain-value = subdomain / IPv4address / IPv6address

path-value = 1*(%x20-3A / %x3C-7E)
extension-av = 1*( %x20-3A / %x3C-7E)
"""


@load_grammar_rulelist(
    [
        ("sane-cookie-date", rfc2616.Rule("rfc1123-date")),
        ("token", rfc2616.Rule("token")),
        ("subdomain", LocalRule("domain-value")),
        ("path-value", LocalRule("path-value")),
        ("extension-av", LocalRule("extension-av")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 6265."""

    grammar = """
OWS            = *( [ obs-fold ] WSP )
                ; "optional" whitespace
obs-fold       = CRLF

cookie-header = "Cookie:" OWS cookie-string OWS
cookie-string = cookie-pair *( ";" SP cookie-pair )

set-cookie-header = "Set-Cookie:" SP set-cookie-string
set-cookie-string = cookie-pair *( ";" SP cookie-av )
cookie-pair       = cookie-name "=" cookie-value
cookie-name       = token
cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                    ; US-ASCII characters excluding CTLs,
                    ; whitespace DQUOTE, comma, semicolon,
                    ; and backslash
token             = <token, defined in [RFC2616], Section 2.2>

cookie-av         = expires-av / max-age-av / domain-av /
                    path-av / secure-av / httponly-av /
                    extension-av
expires-av        = "Expires=" sane-cookie-date
sane-cookie-date  = <rfc1123-date, defined in [RFC2616], Section 3.3.1>
max-age-av        = "Max-Age=" non-zero-digit *DIGIT
                    ; In practice, both expires-av and max-age-av
                    ; are limited to dates representable by the
                    ; user agent.
non-zero-digit    = %x31-39
                    ; digits 1 through 9
domain-av         = "Domain=" domain-value
domain-value      = <subdomain>
                    ; defined in [RFC1034], Section 3.5, as
                    ; enhanced by [RFC1123], Section 2.1
path-av           = "Path=" path-value
path-value        = <any CHAR except CTLs or ";">
secure-av         = "Secure"
httponly-av       = "HttpOnly"
extension-av      = <any CHAR except CTLs or ";">
"""
