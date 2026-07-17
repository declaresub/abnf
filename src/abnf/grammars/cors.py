"""
Collected rules from the Fetch standard.
https://fetch.spec.whatwg.org/#origin-header
https://fetch.spec.whatwg.org/#http-responses

Note that Fetch defines a self-contained grammar for a serialized origin
(serialized-scheme / serialized-host / serialized-port and friends) rather than
reusing scheme / host / port from RFC 3986.  The Origin request header value is
either such a serialized origin or the case-sensitive string "null" (the
serialization of an opaque origin), so Origin admits "null".
"""

from typing import ClassVar

from abnf.parser import Rule as _Rule

from . import rfc9110, rfc9111
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("method", rfc9110.Rule("method")),
        ("field-name", rfc9110.Rule("field-name")),
        ("OWS", rfc9110.Rule("OWS")),
        ("delta-seconds", rfc9111.Rule("delta-seconds")),
    ]
)
class Rule(_Rule):
    """Rules from the Fetch standard."""

    # Fetch defines the CORS response headers using the "#rule" list extension
    # from RFC 9110, Section 5.6.1.  That extension is not part of RFC 5234
    # ABNF, so the affected rules are expanded here to their equivalent
    # RFC 5234 form:
    #     1#field-name = field-name *( OWS "," OWS field-name )
    #      #field-name = [ field-name *( OWS "," OWS field-name ) ]
    #      #method     = [ method *( OWS "," OWS method ) ]
    grammar: ClassVar[list[str] | str] = [
        'serialized-ipv4 = dec-octet "." dec-octet "." dec-octet "." dec-octet',
        'dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35',
        'serialized-ipv6 = 7( h16 ":" ) h16 '
        '/ "::" 5( h16 ":" ) h16 '
        '/ [ h16 ] "::" 4( h16 ":" ) h16 '
        '/ [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) h16 '
        '/ [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) h16 '
        '/ [ *3( h16 ":" ) h16 ] "::" h16 ":" h16 '
        '/ [ *4( h16 ":" ) h16 ] "::" h16 '
        '/ [ *5( h16 ":" ) h16 ] "::"',
        'h16 = "0" / ( non-zero-hex 0*3hex )',
        "non-zero-hex = %x31-39 / %x61-66",
        "hex = %x30-39 / %x61-66",
        "lower-alpha = %x61-7A",
        "lower-alphanum = lower-alpha / DIGIT",
        'domain-label = lower-alphanum / ( lower-alphanum *( lower-alphanum / "-" ) lower-alphanum )',
        'serialized-domain = *( domain-label "." ) domain-label',
        'serialized-scheme = lower-alpha *( lower-alphanum / "+" / "-" / "." )',
        'serialized-host = serialized-ipv4 / "[" serialized-ipv6 "]" / serialized-domain',
        "serialized-port = 1*5DIGIT",
        'serialized-origin = serialized-scheme "://" serialized-host [ ":" serialized-port ]',
        'origin-or-null = serialized-origin / %s"null"',
        "Origin = origin-or-null",
        "Access-Control-Request-Method = method",
        'Access-Control-Request-Headers = field-name *( OWS "," OWS field-name )',
        'wildcard = "*"',
        "Access-Control-Allow-Origin = origin-or-null / wildcard",
        'Access-Control-Allow-Credentials = %s"true"',
        'Access-Control-Expose-Headers = [ field-name *( OWS "," OWS field-name ) ]',
        "Access-Control-Max-Age = delta-seconds",
        'Access-Control-Allow-Methods = [ method *( OWS "," OWS method ) ]',
        'Access-Control-Allow-Headers = [ field-name *( OWS "," OWS field-name ) ]',
        # method       = <method, see [RFC9110], Section 9.1>
        # field-name   = <field-name, see [RFC9110], Section 5.1>
        # OWS          = <OWS, see [RFC9110], Section 5.6.3>
        # delta-seconds = <delta-seconds, see [RFC9111], Section 1.2.2>
    ]
