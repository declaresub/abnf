

"""
Collected rules from RFC 9116
https://www.rfc-editor.org/rfc/rfc9116
"""


from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc3339, rfc3629, rfc3986, rfc5322, rfc5646
from .misc import load_grammar_rules


@load_grammar_rules(
    [
    ("email", rfc5322.Rule("address")),
    ("uri", rfc3986.Rule("uri")),
    ('field-name', rfc5322.Rule("field-name")),
    ('unstructured', rfc5322.Rule('unstructured')),
    ('UTF8-octets', rfc3629.Rule('UTF8-octets')),
    ('UTF8-char', rfc3629.Rule('UTF8-char')),
    ('UTF8-1', rfc3629.Rule('UTF8-1')),
    ('UTF8-2', rfc3629.Rule('UTF8-2')),
    ('UTF8-3', rfc3629.Rule('UTF8-3')),
    ('UTF8-4', rfc3629.Rule('UTF8-4')),
    ('UTF8-tail', rfc3629.Rule('UTF8-tail')),
    ('lang-tag', rfc5646.Rule('langtag')),
    ('date-time', rfc3339.Rule('date-time')),
    ]
)
class Rule(_Rule):
    """Rules from RFC 5987."""

    grammar: ClassVar[Union[list[str], str]] = [
        'body =  signed / unsigned',

        'unsigned =  *line (contact-field eol) *line (expires-field eol) *line [lang-field eol] *line',
        

        #'; signed is the production that should match the OpenPGP clearsigned',
        #'; document',
        'signed =  cleartext-header 1*(hash-header) CRLF cleartext signature',

        'cleartext-header =  %s"-----BEGIN PGP SIGNED MESSAGE-----" CRLF',

        'hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF',

        'hash-alg         =  token',

        'cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)',

        'line-dash        =  ("- ") "-" *UTF8-char-not-cr',

        'line-from        =  ["- "] "From " *UTF8-char-not-cr',

        'line-nodash      =  ["- "] *UTF8-char-not-cr',

        'UTF8-char-not-dash =  UTF8-1-not-dash / UTF8-2 / UTF8-3 / UTF8-4',
        'UTF8-1-not-dash  =  %x00-2C / %x2E-7F',
        'UTF8-char-not-cr =  UTF8-1-not-cr / UTF8-2 / UTF8-3 / UTF8-4',
        'UTF8-1-not-cr    =  %x00-0C / %x0E-7F',

        #'; UTF8 rules from RFC 3629 -- imported above',


        'signature        =  armor-header armor-keys CRLF signature-data armor-tail',

        'armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF',

        'armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF)',

        'armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF',

        'signature-data   =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF)\
                            ; base64; see RFC 4648\
                            ; includes RFC 4880 checksum',

        'line             =  [ (field / comment) ] eol',

        'eol              =  *WSP [CR] LF',

        #'field            =  ; optional fields\
        'field            =  ack-field / can-field / contact-field / encryption-field / hiring-field / policy-field / ext-field',

        'fs               =  ":"',

        'comment          =  "#" *(WSP / VCHAR / %x80-FFFFF)',

        'ack-field        =  "Acknowledgments" fs SP uri',

        'can-field        =  "Canonical" fs SP uri',

        'contact-field    =  "Contact" fs SP uri',

        'expires-field    =  "Expires" fs SP date-time',

        'encryption-field =  "Encryption" fs SP uri',

        'hiring-field     =  "Hiring" fs SP uri',

        'lang-field       =  "Preferred-Languages" fs SP lang-values',

        'policy-field     =  "Policy" fs SP uri',

        #date-time        =  < imported from Section 5.6 of [RFC3339] >

        #lang-tag         =  < Language-Tag from Section 2.1 of [RFC5646] >

        'lang-values      =  lang-tag *(*WSP "," *WSP lang-tag)',

        #uri              =  < URI as per Section 3 of [RFC3986] >

        'ext-field        =  field-name fs SP unstructured',

        #field-name       =  < imported from Section 3.6.8 of [RFC5322] >

        #unstructured     =  < imported from Section 3.2.5 of [RFC5322] >

        #token            =  < imported from Section 5.1 of [RFC2045] >
        # definition from RFC 2045:
        # token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
        #        or tspecials>

        # tspecials :=  "(" / ")" / "<" / ">" / "@" /
        #           "," / ";" / ":" / "\" / <">
        #           "/" / "[" / "]" / "?" / "="
        #          ; Must be in quoted-string,
        #          ; to use within parameter values

        
        'token-char = %x21-27 / %x2A-2B / %x30-39 / %x41-5A / %x5E-7E',
        'token = 1*token-char',


# core rules included in this grammar are omitted.

    ]
