"""
Collected rules from RFC 7230, Appendix B.
https://tools.ietf.org/html/rfc7230#appendix-B

Note that this RFC is obsolete as of June 2022, replaced by 
https://www.rfc-editor.org/rfc/rfc9110.
"""

from abnf.parser import Rule as _Rule
from . import rfc3986
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("URI-reference", rfc3986.Rule("URI-reference")),
        ("absolute-URI", rfc3986.Rule("absolute-URI")),
        ("authority", rfc3986.Rule("authority")),
        ("fragment", rfc3986.Rule("fragment")),
        ("path-abempty", rfc3986.Rule("path-abempty")),
        ("port", rfc3986.Rule("port")),
        ("query", rfc3986.Rule("query")),
        ("relative-part", rfc3986.Rule("relative-part")),
        ("scheme", rfc3986.Rule("scheme")),
        ("segment", rfc3986.Rule("segment")),
        ("uri-host", rfc3986.Rule("host")),
    ]
)
class Rule(_Rule):
    """Parser rules for grammar from RFC 7230."""

    grammar = [
        "BWS = OWS",
        'Connection = *( "," OWS ) connection-option *( OWS "," [ OWS connection-option ] )',
        "Content-Length = 1*DIGIT",
        "HTTP-message = start-line *( header-field CRLF ) CRLF [ message-body ]",
        "HTTP-name = %x48.54.54.50",
        'HTTP-version = HTTP-name "/" DIGIT "." DIGIT',
        'Host = uri-host [ ":" port ]',
        "OWS = *( SP / HTAB )",
        "RWS = 1*( SP / HTAB )",
        'TE = [ ( "," / t-codings ) *( OWS "," [ OWS t-codings ] ) ]',
        'Trailer = *( "," OWS ) field-name *( OWS "," [ OWS field-name ] )',
        'Transfer-Encoding = *( "," OWS ) transfer-coding *( OWS "," [ OWS transfer-coding ] )',
        # URI-reference = <URI-reference, see [RFC3986], Section 4.1>',
        'Upgrade = *( "," OWS ) protocol *( OWS "," [ OWS protocol ] )',
        'Via = *( "," OWS ) ( received-protocol RWS received-by [ RWS comment ] ) *( OWS "," [ OWS ( received-protocol RWS received-by [ RWS comment ] ) ] )',
        # absolute-URI = <absolute-URI, see [RFC3986], Section 4.3>',
        "absolute-form = absolute-URI",
        'absolute-path = 1*( "/" segment )',
        'asterisk-form = "*"',
        # authority = <authority, see [RFC3986], Section 3.2>',
        "authority-form = authority",
        "chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF",
        "chunk-data = 1*OCTET",
        'chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )',
        "chunk-ext-name = token",
        "chunk-ext-val = token / quoted-string",
        "chunk-size = 1*HEXDIG",
        "chunked-body = *chunk last-chunk trailer-part CRLF",
        'comment = "(" *( ctext / quoted-pair / comment ) ")"',
        "connection-option = token",
        "ctext = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text",
        "field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]",
        "field-name = token",
        "field-value = *( field-content / obs-fold )",
        "field-vchar = VCHAR / obs-text",
        # fragment = <fragment, see [RFC3986], Section 3.5>',
        'header-field = field-name ":" OWS field-value OWS',
        'http-URI = "http://" authority path-abempty [ "?" query ] [ "#" fragment ]',
        'https-URI = "https://" authority path-abempty [ "?" query ] [ "#" fragment ]',
        'last-chunk = 1*"0" [ chunk-ext ] CRLF',
        "message-body = *OCTET",
        "method = token",
        "obs-fold = CRLF 1*( SP / HTAB )",
        "obs-text = %x80-FF",
        'origin-form = absolute-path [ "?" query ]',
        'partial-URI = relative-part [ "?" query ]',
        # path-abempty = <path-abempty, see [RFC3986], Section 3.3>',
        # port = <port, see [RFC3986], Section 3.2.3>',
        'protocol = protocol-name [ "/" protocol-version ]',
        "protocol-name = token",
        "protocol-version = token",
        "pseudonym = token",
        'qdtext = HTAB / SP / "!" / %x23-5B / %x5D-7E / obs-text',
        # query = <query, see [RFC3986], Section 3.4>',
        'quoted-pair = "\\" ( HTAB / SP / VCHAR / obs-text )',
        "quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE",
        'rank = ( "0" [ "." *3DIGIT ] ) / ( "1" [ "." *3"0" ] )',
        "reason-phrase = *( HTAB / SP / VCHAR / obs-text )",
        'received-by = ( uri-host [ ":" port ] ) / pseudonym',
        'received-protocol = [ protocol-name "/" ] protocol-version',
        # relative-part = <relative-part, see [RFC3986], Section 4.2>',
        "request-line = method SP request-target SP HTTP-version CRLF",
        "request-target = origin-form / absolute-form / authority-form / asterisk-form",
        # scheme = <scheme, see [RFC3986], Section 3.1>',
        # segment = <segment, see [RFC3986], Section 3.3>',
        "start-line = request-line / status-line",
        "status-code = 3DIGIT",
        "status-line = HTTP-version SP status-code SP reason-phrase CRLF",
        't-codings = "trailers" / ( transfer-coding [ t-ranking ] )',
        't-ranking = OWS ";" OWS "q=" rank',
        'tchar = "!" / "#" / "$" / "%" / "&" / "\'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA',
        "token = 1*tchar",
        "trailer-part = *( header-field CRLF )",
        'transfer-coding = "chunked" / "compress" / "deflate" / "gzip" / transfer-extension',
        'transfer-extension = token *( OWS ";" OWS transfer-parameter )',
        'transfer-parameter = token BWS "=" BWS ( token / quoted-string )',
        #'uri-host = host' #<host, see [RFC3986], Section 3.2.2>',
    ]
