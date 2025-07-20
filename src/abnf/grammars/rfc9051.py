from typing import ClassVar, Union

from abnf.grammars import rfc3629
from abnf.parser import Rule as _Rule

from . import rfc5322
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        # Email-related rules from RFC 5322
        ("atom", rfc5322.Rule("atom")),
        # Rules from RFC 3629 for UTF-8 encoding
        ("UTF8-char", rfc3629.Rule("UTF8-char")),
        ("UTF8-2", rfc3629.Rule("UTF8-2")),
        ("UTF8-3", rfc3629.Rule("UTF8-3")),
        ("UTF8-4", rfc3629.Rule("UTF8-4")),
    ]
)
class Rule(_Rule):
    """Rules for RFC 9051 parsing."""

    grammar: ClassVar[Union[list[str], str]] = [
        'address = "(" addr-name SP addr-adl SP addr-mailbox SP addr-host ")"',
        "addr-adl = nstring",
        "addr-host = nstring",
        "addr-mailbox = nstring",
        "addr-name = nstring",
        'append = "APPEND" SP mailbox [SP flag-list] [SP date-time] SP '
        "literal",
        "append-uid = uniqueid",
        "astring = 1*ASTRING-CHAR / string",
        "ASTRING-CHAR = ATOM-CHAR / resp-specials",
        "atom = 1*ATOM-CHAR",
        "ATOM-CHAR = %x21 / %x23-24 / %x26-27 / %x2B-39 / %x3B-5B / "
        "%x5E-7A / %x7C",
        'atom-specials = "(" / ")" / "{" / SP / CTL / list-wildcards / '
        "quoted-specials / resp-specials",
        'authenticate = "AUTHENTICATE" SP auth-type [SP initial-resp] '
        "*(CRLF base64)",
        "auth-type = atom",
        "base64 = *(4base64-char) [base64-terminal]",
        'base64-char = ALPHA / DIGIT / "+" / "/"',
        'base64-terminal = (2base64-char "==") / (3base64-char "=")',
        'body = "(" (body-type-1part / body-type-mpart) ")"',
        'body-extension = nstring / number / number64 / "(" body-extension '
        '*(SP body-extension) ")"',
        "body-ext-1part = body-fld-md5 [SP body-fld-dsp [SP body-fld-lang "
        "[SP body-fld-loc *(SP body-extension)]]]",
        "body-ext-mpart = body-fld-param [SP body-fld-dsp [SP body-fld-lang "
        "[SP body-fld-loc *(SP body-extension)]]]",
        "body-fields = body-fld-param SP body-fld-id SP body-fld-desc SP "
        "body-fld-enc SP body-fld-octets",
        "body-fld-desc = nstring",
        'body-fld-dsp = "(" string SP body-fld-param ")" / nil',
        'body-fld-enc = (DQUOTE ("7BIT" / "8BIT" / "BINARY" / "BASE64"/ '
        '"QUOTED-PRINTABLE") DQUOTE) / string',
        "body-fld-id = nstring",
        'body-fld-lang = nstring / "(" string *(SP string) ")"',
        "body-fld-loc = nstring",
        "body-fld-lines = number64",
        "body-fld-md5 = nstring",
        "body-fld-octets = number",
        'body-fld-param = "(" string SP string *(SP string SP string) ")" / '
        "nil",
        "body-type-1part = (body-type-basic / body-type-msg / body-type-text) "
        "[SP body-ext-1part]",
        "body-type-basic = media-basic SP body-fields",
        "body-type-mpart = 1*body SP media-subtype [SP body-ext-mpart]",
        "body-type-msg = media-message SP body-fields SP envelope SP body SP "
        "body-fld-lines",
        "body-type-text = media-text SP body-fields SP body-fld-lines",
        'capability = ("AUTH=" auth-type) / atom',
        'capability-data = "CAPABILITY" *(SP capability) SP "IMAP4rev2" '
        "*(SP capability)",
        "CHAR8 = %x01-ff",
        "charset = atom / quoted",
        'childinfo-extended-item = "CHILDINFO" SP "(" '
        "list-select-base-opt-quoted *(SP list-select-base-opt-quoted) "
        '")"',
        'child-mbox-flag = "\\HasChildren" / "\\HasNoChildren"',
        "command = tag SP (command-any / command-auth / command-nonauth / "
        "command-select) CRLF",
        'command-any = "CAPABILITY" / "LOGOUT" / "NOOP"',
        "command-auth = append / create / delete / enable / examine / list / "
        "namespace-command / rename / select / status / subscribe / "
        "unsubscribe / idle",
        'command-nonauth = login / authenticate / "STARTTLS"',
        'command-select = "CLOSE" / "UNSELECT" / "EXPUNGE" / copy / move / '
        "fetch / store / search / uid",
        'continue-req = "+" SP (resp-text / base64) CRLF',
        'copy = "COPY" SP sequence-set SP mailbox',
        'create = "CREATE" SP mailbox',
        "date = date-text / DQUOTE date-text DQUOTE",
        "date-day = 1*2DIGIT",
        "date-day-fixed = (SP DIGIT) / 2DIGIT",
        'date-month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / '
        '"Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"',
        'date-text = date-day "-" date-month "-" date-year',
        "date-year = 4DIGIT",
        'date-time = DQUOTE date-day-fixed "-" date-month "-" date-year SP '
        "time SP zone DQUOTE",
        'delete = "DELETE" SP mailbox',
        "digit-nz = %x31-39",
        "eitem-standard-tag = atom",
        'eitem-vendor-tag = vendor-token "-" atom',
        'enable = "ENABLE" 1*(SP capability)',
        'enable-data = "ENABLED" *(SP capability)',
        'envelope = "(" env-date SP env-subject SP env-from SP env-sender SP '
        "env-reply-to SP env-to SP env-cc SP env-bcc SP env-in-reply-to SP "
        'env-message-id ")"',
        'env-bcc = "(" 1*address ")" / nil',
        'env-cc = "(" 1*address ")" / nil',
        "env-date = nstring",
        'env-from = "(" 1*address ")" / nil',
        "env-in-reply-to = nstring",
        "env-message-id = nstring",
        'env-reply-to = "(" 1*address ")" / nil',
        'env-sender = "(" 1*address ")" / nil',
        "env-subject = nstring",
        'env-to = "(" 1*address ")" / nil',
        'esearch-response = "ESEARCH" [search-correlator] [SP "UID"] '
        "*(SP search-return-data)",
        'examine = "EXAMINE" SP mailbox',
        'fetch = "FETCH" SP sequence-set SP ("ALL" / "FULL" / "FAST" / '
        'fetch-att / "(" fetch-att *(SP fetch-att) ")")',
        'fetch-att = "ENVELOPE" / "FLAGS" / "INTERNALDATE" / "RFC822.SIZE" / '
        '"BODY" ["STRUCTURE"] / "UID" / "BODY" section [partial] / '
        '"BODY.PEEK" section [partial] / "BINARY" [".PEEK"] section-binary '
        '[partial] / "BINARY.SIZE" section-binary',
        'flag = "\\Answered" / "\\Flagged" / "\\Deleted" / "\\Seen" / '
        '"\\Draft" / flag-keyword / flag-extension',
        'flag-extension = "\\" atom',
        "flag-fetch = flag / obsolete-flag-recent",
        'flag-keyword = "$MDNSent" / "$Forwarded" / "$Junk" / "$NotJunk" / '
        '"$Phishing" / atom',
        'flag-list = "(" [flag *(SP flag)] ")"',
        'flag-perm = flag / "*"',
        'greeting = "*" SP (resp-cond-auth / resp-cond-bye) CRLF',
        "header-fld-name = astring",
        'header-list = "(" header-fld-name *(SP header-fld-name) ")"',
        'idle = "IDLE" CRLF "DONE"',
        'initial-resp = (base64 / "=")',
        'list = "LIST" [SP list-select-opts] SP mailbox SP mbox-or-pat '
        "[SP list-return-opts]",
        "list-mailbox = 1*list-char / string",
        "list-char = ATOM-CHAR / list-wildcards / resp-specials",
        "list-return-opt = return-option",
        'list-return-opts = "RETURN" SP "(" [list-return-opt '
        '*(SP list-return-opt)] ")"',
        'list-select-base-opt = "SUBSCRIBED" / option-extension',
        "list-select-base-opt-quoted = DQUOTE list-select-base-opt DQUOTE",
        'list-select-independent-opt = "REMOTE" / option-extension',
        'list-select-mod-opt = "RECURSIVEMATCH" / option-extension',
        "list-select-opt = list-select-base-opt / "
        "list-select-independent-opt / list-select-mod-opt",
        'list-select-opts = "(" [(*(list-select-opt SP) '
        "list-select-base-opt *(SP list-select-opt)) / "
        "(list-select-independent-opt "
        '*(SP list-select-independent-opt))] ")"',
        'list-wildcards = "%" / "*"',
        'literal = "{" number64 ["+"] "}" CRLF *CHAR8',
        'literal8 = "~{" number64 "}" CRLF *OCTET',
        'login = "LOGIN" SP userid SP password',
        'mailbox = "INBOX" / astring',
        'mailbox-data = "FLAGS" SP flag-list / "LIST" SP mailbox-list / '
        'esearch-response / "STATUS" SP mailbox SP "(" [status-att-list] '
        '")" / number SP "EXISTS" / namespace-response / '
        "obsolete-search-response / obsolete-recent-response",
        'mailbox-list = "(" [mbx-list-flags] ")" SP (DQUOTE QUOTED-CHAR '
        "DQUOTE / nil) SP mailbox [SP mbx-list-extended]",
        'mbx-list-extended = "(" [mbox-list-extended-item '
        '*(SP mbox-list-extended-item)] ")"',
        "mbox-list-extended-item = mbox-list-extended-item-tag SP "
        "tagged-ext-val",
        "mbox-list-extended-item-tag = astring",
        "mbox-or-pat =  list-mailbox / patterns",
        "mbx-list-flags = *(mbx-list-oflag SP) mbx-list-sflag "
        "*(SP mbx-list-oflag) / mbx-list-oflag *(SP mbx-list-oflag)",
        'mbx-list-oflag = "\\Noinferiors" / child-mbox-flag / '
        '"\\Subscribed" / "\\Remote" / flag-extension',
        'mbx-list-sflag = "\\NonExistent" / "\\Noselect" / "\\Marked" / '
        '"\\Unmarked"',
        'media-basic = ((DQUOTE ("APPLICATION" / "AUDIO" / "IMAGE" / '
        '"FONT" / "MESSAGE" / "MODEL" / "VIDEO") DQUOTE) / string) SP '
        "media-subtype",
        'media-message = DQUOTE "MESSAGE" DQUOTE SP DQUOTE ("RFC822" / '
        '"GLOBAL") DQUOTE',
        "media-subtype = string",
        'media-text = DQUOTE "TEXT" DQUOTE SP media-subtype',
        'message-data = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))',
        'move = "MOVE" SP sequence-set SP mailbox',
        'msg-att = "(" (msg-att-dynamic / msg-att-static) '
        '*(SP (msg-att-dynamic / msg-att-static)) ")"',
        'msg-att-dynamic = "FLAGS" SP "(" [flag-fetch *(SP flag-fetch)] ")"',
        'msg-att-static = "ENVELOPE" SP envelope / "INTERNALDATE" SP '
        'date-time / "RFC822.SIZE" SP number64 / "BODY" ["STRUCTURE"] SP '
        'body / "BODY" section ["<" number ">"] SP nstring / "BINARY" '
        'section-binary SP (nstring / literal8) / "BINARY.SIZE" '
        'section-binary SP number / "UID" SP uniqueid',
        "name-component = 1*UTF8-CHAR",
        'namespace = nil / "(" 1*namespace-descr ")"',
        'namespace-command = "NAMESPACE"',
        'namespace-descr = "(" string SP (DQUOTE QUOTED-CHAR DQUOTE / nil) '
        "[namespace-response-extensions] "
        '")"',
        "namespace-response-extensions = *namespace-response-extension",
        'namespace-response-extension = SP string SP "(" string '
        '*(SP string) ")"',
        'namespace-response = "NAMESPACE" SP namespace SP namespace SP '
        "namespace",
        'nil = "NIL"',
        "nstring = string / nil",
        "number = 1*DIGIT",
        "number64 = 1*DIGIT",
        "nz-number = digit-nz *DIGIT",
        "nz-number64 = digit-nz *DIGIT",
        'obsolete-flag-recent = "\\Recent"',
        'obsolete-recent-response = number SP "RECENT"',
        'obsolete-search-response = "SEARCH" *(SP nz-number)',
        'oldname-extended-item = "OLDNAME" SP "(" mailbox ")"',
        "option-extension = (option-standard-tag / option-vendor-tag) "
        "[SP option-value]",
        "option-standard-tag = atom",
        "option-val-comp = astring / option-val-comp *(SP option-val-comp) "
        '/ "(" option-val-comp ")"',
        'option-value = "(" option-val-comp ")"',
        'option-vendor-tag = vendor-token "-" atom',
        'partial-range = number64 ["." nz-number64]',
        'partial = "<" number64 "." nz-number64 ">"',
        "password = astring",
        'patterns = "(" list-mailbox ")"',
        "quoted = DQUOTE *QUOTED-CHAR DQUOTE",
        "QUOTED-CHAR = %x01-09 / %x0B-0C / %x0E-21 / %x23-5B / %x5D-FF / "
        '"\\" quoted-specials / UTF8-2 / UTF8-3 / UTF8-4',
        'quoted-specials = DQUOTE / "\\"',
        'rename = "RENAME" SP mailbox SP mailbox',
        "response = *(continue-req / response-data) response-done",
        'response-data = "*" SP (resp-cond-state / resp-cond-bye / '
        "mailbox-data / message-data / capability-data / enable-data) CRLF",
        "response-done = response-tagged / response-fatal",
        'response-fatal = "*" SP resp-cond-bye CRLF',
        "response-tagged = tag SP resp-cond-state CRLF",
        'resp-code-apnd = "APPENDUID" SP nz-number SP append-uid',
        'resp-code-copy = "COPYUID" SP nz-number SP uid-set SP uid-set',
        'resp-cond-auth = ("OK" / "PREAUTH") SP resp-text',
        'resp-cond-bye = "BYE" SP resp-text',
        'resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text',
        'resp-specials = "]"',
        'resp-text = ["[" resp-text-code "]" SP] [text]',
        'resp-text-code = "ALERT" / "BADCHARSET" [SP "(" charset '
        '*(SP charset) ")"] / capability-data / "PARSE" / '
        '"PERMANENTFLAGS" SP "(" [flag-perm *(SP flag-perm)] ")" / '
        '"READ-ONLY" / "READ-WRITE" / "TRYCREATE" / "UIDNEXT" SP '
        'nz-number / "UIDVALIDITY" SP nz-number / resp-code-apnd / '
        'resp-code-copy / "UIDNOTSTICKY" / "UNAVAILABLE" / '
        '"AUTHENTICATIONFAILED" / "AUTHORIZATIONFAILED" / "EXPIRED" / '
        '"PRIVACYREQUIRED" / "CONTACTADMIN" / "NOPERM" / "INUSE" / '
        '"EXPUNGEISSUED" / "CORRUPTION" / "SERVERBUG" / "CLIENTBUG" / '
        '"CANNOT" / "LIMIT" / "OVERQUOTA" / "ALREADYEXISTS" / '
        '"NONEXISTENT" / "NOTSAVED" / "HASCHILDREN" / "CLOSED" / '
        '"UNKNOWN-CTE" / atom [SP 1*<any TEXT-CHAR except "]">]',
        'return-option = "SUBSCRIBED" / "CHILDREN" / status-option / '
        "option-extension",
        'search = "SEARCH" [search-return-opts] SP search-program',
        'search-correlator = SP "(" "TAG" SP tag-string ")"',
        'search-key = "ALL" / "ANSWERED" / "BCC" SP astring / "BEFORE" SP '
        'date / "BODY" SP astring / "CC" SP astring / "DELETED" / '
        '"FLAGGED" / "FROM" SP astring / "KEYWORD" SP flag-keyword / '
        '"ON" SP date / "SEEN" / "SINCE" SP date / "SUBJECT" SP astring / '
        '"TEXT" SP astring / "TO" SP astring / "UNANSWERED" / "UNDELETED" '
        '/ "UNFLAGGED" / "UNKEYWORD" SP flag-keyword / "UNSEEN" / "DRAFT" '
        '/ "HEADER" SP header-fld-name SP astring / "LARGER" SP number64 / '
        '"NOT" SP search-key / "OR" SP search-key SP search-key / '
        '"SENTBEFORE" SP date / "SENTON" SP date / "SENTSINCE" SP date / '
        '"SMALLER" SP number64 / "UID" SP sequence-set / "UNDRAFT" / '
        'sequence-set / "(" search-key *(SP search-key) ")"',
        "search-modifier-name = tagged-ext-label",
        "search-mod-params = tagged-ext-val",
        'search-program = ["CHARSET" SP charset SP] search-key '
        "*(SP search-key)",
        "search-ret-data-ext = search-modifier-name SP search-return-value",
        'search-return-data = "MIN" SP nz-number / "MAX" SP nz-number / '
        '"ALL" SP sequence-set / "COUNT" SP number / search-ret-data-ext',
        'search-return-opts = SP "RETURN" SP "(" [search-return-opt '
        '*(SP search-return-opt)] ")"',
        'search-return-opt = "MIN" / "MAX" / "ALL" / "COUNT" / "SAVE" / '
        "search-ret-opt-ext",
        "search-ret-opt-ext = search-modifier-name [SP search-mod-params]",
        "search-return-value = tagged-ext-val",
        'section = "[" [section-spec] "]"',
        'section-binary = "[" [section-part] "]"',
        'section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP '
        'header-list / "TEXT"',
        'section-part = nz-number *("." nz-number)',
        'section-spec = section-msgtext / (section-part ["." section-text])',
        'section-text = section-msgtext / "MIME"',
        'select = "SELECT" SP mailbox',
        'seq-number = nz-number / "*"',
        'seq-range = seq-number ":" seq-number',
        'sequence-set = (seq-number / seq-range) ["," sequence-set] / '
        "seq-last-command",
        'seq-last-command = "$"',
        'status = "STATUS" SP mailbox SP "(" status-att *(SP status-att) ")"',
        'status-att = "MESSAGES" / "UIDNEXT" / "UIDVALIDITY" / "UNSEEN" / '
        '"DELETED" / "SIZE"',
        'status-att-val = ("MESSAGES" SP number) / ("UIDNEXT" SP nz-number) '
        '/ ("UIDVALIDITY" SP nz-number) / ("UNSEEN" SP number) / '
        '("DELETED" SP number) / ("SIZE" SP number64)',
        "status-att-list = status-att-val *(SP status-att-val)",
        'status-option = "STATUS" SP "(" status-att *(SP status-att) ")"',
        'store = "STORE" SP sequence-set SP store-att-flags',
        'store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP '
        "(flag-list / (flag *(SP flag)))",
        "string = quoted / literal",
        'subscribe = "SUBSCRIBE" SP mailbox',
        "tag = 1*TAG-CHAR",
        "TAG-CHAR = %x21 / %x23-24 / %x26-27 / %x2C-39 / %x3B-5B / "
        "%x5D / %x5E-7A / %x7C",
        "tag-string = astring",
        "tagged-ext-label = tagged-label-fchar *tagged-label-char",
        'tagged-label-fchar = ALPHA / "-" / "_" / "."',
        'tagged-label-char = tagged-label-fchar / DIGIT / ":"',
        "tagged-ext-comp = astring / tagged-ext-comp *(SP tagged-ext-comp) "
        '/ "(" tagged-ext-comp ")"',
        "tagged-ext-simple = sequence-set / number / number64",
        'tagged-ext-val = tagged-ext-simple / "(" [tagged-ext-comp] ")"',
        "text = 1*(TEXT-CHAR / UTF8-2 / UTF8-3 / UTF8-4)",
        "TEXT-CHAR = %x01-09 / %x0B-0C / %x0E-FF",
        'time = 2DIGIT ":" 2DIGIT ":" 2DIGIT',
        'uid = "UID" SP (copy / move / fetch / search / store / uid-expunge)',
        'uid-expunge = "EXPUNGE" SP sequence-set',
        'uid-set = (uniqueid / uid-range) *("," uid-set)',
        'uid-range = (uniqueid ":" uniqueid)',
        "uniqueid = nz-number",
        'unsubscribe = "UNSUBSCRIBE" SP mailbox',
        "userid = astring",
        'vendor-token = "vendor." name-component',
        'zone = ("+" / "-") 4DIGIT',
    ]
