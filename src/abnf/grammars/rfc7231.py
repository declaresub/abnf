"""
Collected rules from RFC 7231, Appendix c, D.
https://tools.ietf.org/html/rfc7231#appendix-C

Note that this RFC is obsolete as of June 2022, replaced by 
https://www.rfc-editor.org/rfc/rfc9110.
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc4647, rfc5322, rfc5646, rfc7230
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("language-range", rfc4647.Rule("language-range")),
        ("mailbox", rfc5322.Rule("mailbox")),
        ("language-tag", rfc5646.Rule("language-tag")),
        ("BWS", rfc7230.Rule("BWS")),
        ("OWS", rfc7230.Rule("OWS")),
        ("RWS", rfc7230.Rule("RWS")),
        ("URI-reference", rfc7230.Rule("URI-reference")),
        ("absolute-URI", rfc7230.Rule("absolute-URI")),
        ("comment", rfc7230.Rule("comment")),
        # see https://www.rfc-editor.org/errata/eid4225 for field-name.
        ("field-name", rfc7230.Rule("field-name")),
        ("partial-URI", rfc7230.Rule("partial-URI")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("token", rfc7230.Rule("token")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 7231."""

    grammar: ClassVar[Union[list[str], str]] = [
        'Accept = [ ( "," / ( media-range [ accept-params ] ) ) *( OWS "," [ OWS ( media-range [ accept-params ] ) ] ) ]',
        'Accept-Charset = *( "," OWS ) ( ( charset / "*" ) [ weight ] ) *( OWS "," [ OWS ( ( charset / "*" ) [ weight ] ) ] )',
        'Accept-Encoding = [ ( "," / ( codings [ weight ] ) ) *( OWS "," [ OWS ( codings [ weight ] ) ] ) ]',
        'Accept-Language = *( "," OWS ) ( language-range [ weight ] ) *( OWS "," [ OWS ( language-range [ weight ] ) ] )',
        'Allow = [ ( "," / method ) *( OWS "," [ OWS method ] ) ]',
        # BWS = <BWS, see [RFC7230], Section 3.2.3>
        'Content-Encoding = *( "," OWS ) content-coding *( OWS "," [ OWS content-coding ] )',
        'Content-Language = *( "," OWS ) language-tag *( OWS "," [ OWS language-tag ] )',
        "Content-Location = absolute-URI / partial-URI",
        "Content-Type = media-type",
        "Date = HTTP-date",
        'Expect = "100-continue"',
        "From = mailbox",
        "GMT = %x47.4D.54 ",
        "HTTP-date = IMF-fixdate / obs-date",
        'IMF-fixdate = day-name "," SP date1 SP time-of-day SP GMT',
        "Location = URI-reference",
        "Max-Forwards = 1*DIGIT",
        # OWS = <OWS, see [RFC7230], Section 3.2.3>
        # RWS = <RWS, see [RFC7230], Section 3.2.3>
        "Referer = absolute-URI / partial-URI",
        "Retry-After = HTTP-date / delay-seconds",
        "Server = product *( RWS ( product / comment ) )",
        # URI-reference = <URI-reference, see [RFC7230], Section 2.7>
        "User-Agent = product *( RWS ( product / comment ) )",
        'Vary = "*" / ( *( "," OWS ) field-name *( OWS "," [ OWS field-name ] ) )',
        # absolute-URI = <absolute-URI, see [RFC7230], Section 2.7>
        'accept-ext = OWS ";" OWS token [ "=" ( token / quoted-string ) ]',
        "accept-params = weight *accept-ext",
        "asctime-date = day-name SP date3 SP time-of-day SP year",
        "charset = token",
        'codings = content-coding / "identity" / "*"',
        # comment = <comment, see [RFC7230], Section 3.2.6>
        "content-coding = token",
        "date1 = day SP month SP year",
        'date2 = day "-" month "-" 2DIGIT',
        "date3 = month SP ( 2DIGIT / ( SP DIGIT ) )",
        "day = 2DIGIT",
        "day-name = %x4D.6F.6E / %x54.75.65 / %x57.65.64 / %x54.68.75 / %x46.72.69 / %x53.61.74 / %x53.75.6E ",
        "day-name-l = %x4D.6F.6E.64.61.79 / %x54.75.65.73.64.61.79 / %x57.65.64.6E.65.73.64.61.79 / %x54.68.75.72.73.64.61.79 / %x46.72.69.64.61.79 / %x53.61.74.75.72.64.61.79 / %x53.75.6E.64.61.79 ",
        "delay-seconds = 1*DIGIT",
        # field-name = <comment, see [RFC7230], Section 3.2> -- also see https://www.rfc-editor.org/errata/eid4225 .
        "hour = 2DIGIT",
        # language-range = <language-range, see [RFC4647], Section 2.1>
        # language-tag = <Language-Tag, see [RFC5646], Section 2.1>',
        # mailbox = <mailbox, see [RFC5322], Section 3.4>
        'media-range = ( "*/*" / ( type "/*" ) / ( type "/" subtype ) ) *( OWS ";" OWS parameter )',
        'media-type = type "/" subtype *( OWS ";" OWS parameter )',
        "method = token",
        "minute = 2DIGIT",
        "month = %x4A.61.6E / %x46.65.62 / %x4D.61.72 / %x41.70.72 / %x4D.61.79 / %x4A.75.6E / %x4A.75.6C / %x41.75.67 / %x53.65.70 / %x4F.63.74 / %x4E.6F.76 / %x44.65.63 ",
        "obs-date = rfc850-date / asctime-date",
        'parameter = token "=" ( token / quoted-string )',
        # partial-URI = <partial-URI, see [RFC7230], Section 2.7>
        'product = token [ "/" product-version ]',
        "product-version = token",
        # quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>
        'qvalue = ( "0" [ "." *3DIGIT ] ) / ( "1" [ "." *3"0" ] )',
        'rfc850-date = day-name-l "," SP date2 SP time-of-day SP GMT',
        "second = 2DIGIT",
        "subtype = token",
        'time-of-day = hour ":" minute ":" second',
        # token = <token, see [RFC7230], Section 3.2.6>
        "type = token",
        'weight = OWS ";" OWS "q=" qvalue',
        "year = 4DIGIT",
    ]
