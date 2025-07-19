import pytest

from abnf.grammars import rfc9051
from abnf.parser import ParseError


class TestRFC9051Numbers:
    """Test cases for RFC 9051 number and digit grammar rules."""

    @pytest.mark.parametrize("src", ["1", "5", "9"])
    def test_digit_nz(self, src: str) -> None:
        """Test digit-nz rule for non-zero digits."""
        rfc9051.Rule("digit-nz").parse_all(src)

    @pytest.mark.parametrize("src", ["0"])
    def test_digit_nz_fails_for_zero(self, src: str) -> None:
        """Test digit-nz rule fails for zero."""
        with pytest.raises(ParseError):
            rfc9051.Rule("digit-nz").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "12", "123", "9999"])
    def test_number(self, src: str) -> None:
        """Test number rule for sequences of digits."""
        rfc9051.Rule("number").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "12", "123", "9999"])
    def test_number64(self, src: str) -> None:
        """Test number64 rule for sequences of digits."""
        rfc9051.Rule("number64").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "12", "123", "9999"])
    def test_nz_number(self, src: str) -> None:
        """Test nz-number rule for non-zero leading numbers."""
        rfc9051.Rule("nz-number").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "12", "123", "9999"])
    def test_nz_number64(self, src: str) -> None:
        """Test nz-number64 rule for non-zero leading numbers."""
        rfc9051.Rule("nz-number64").parse_all(src)

    @pytest.mark.parametrize("src", ["0"])
    def test_nz_number_fails_for_zero(self, src: str) -> None:
        """Test nz-number rule fails for zero."""
        with pytest.raises(ParseError):
            rfc9051.Rule("nz-number").parse_all(src)


class TestRFC9051Strings:
    """Test cases for RFC 9051 string and text grammar rules."""

    def test_nil(self) -> None:
        """Test NIL rule."""
        rfc9051.Rule("nil").parse_all("NIL")

    @pytest.mark.parametrize("src", ["A", "a", "0", "+", "/", "\r", "\n"])
    def test_char(self, src: str) -> None:
        """Test CHAR rule."""
        rfc9051.Rule("char").parse_all(src)

    @pytest.mark.parametrize("src", ["A", "a", "0", "+", "/"])
    def test_text_char(self, src: str) -> None:
        """Test text-char rule for valid text characters."""
        rfc9051.Rule("TEXT-CHAR").parse_all(src)

    @pytest.mark.parametrize("src", ["\r", "\n"])
    def test_text_char_fails_for_invalid(self, src: str) -> None:
        """Test text-char rule fails for invalid characters."""
        with pytest.raises(ParseError):
            rfc9051.Rule("TEXT-CHAR").parse_all(src)

    @pytest.mark.parametrize("src", ["A", "a", "0", "+", "/", '\\"', "\\\\"])
    def test_quoted_char(self, src: str) -> None:
        """Test quoted-char rule for valid quoted characters."""
        rfc9051.Rule("QUOTED-CHAR").parse_all(src)

    @pytest.mark.parametrize("src", ["\r", "\n", '"', "\\"])
    def test_quoted_char_fails_for_invalid(self, src: str) -> None:
        """Test quoted-char rule fails for invalid characters."""
        with pytest.raises(ParseError):
            rfc9051.Rule("QUOTED-CHAR").parse_all(src)

    @pytest.mark.parametrize(
        "src", ["NIL", "{5}\r\nhello", "{12}\r\ntest string"]
    )
    def test_nstring(self, src: str) -> None:
        """Test nstring rule for NIL or literal strings."""
        rfc9051.Rule("nstring").parse_all(src)

    @pytest.mark.parametrize("src", ['"hello"', '"test string"', '""'])
    def test_quoted(self, src: str) -> None:
        """Test quoted rule for double-quoted strings."""
        rfc9051.Rule("quoted").parse_all(src)

    @pytest.mark.parametrize("src", ['"hello"', "{5}\r\nhello"])
    def test_string(self, src: str) -> None:
        """Test string rule for quoted or literal strings."""
        rfc9051.Rule("string").parse_all(src)

    @pytest.mark.parametrize("src", ['"hello"', "{5}\r\nhello"])
    def test_astring(self, src: str) -> None:
        """Test astring rule for quoted or literal strings."""
        rfc9051.Rule("astring").parse_all(src)


class TestRFC9051:
    """Test cases for RFC 9051 IMAP4rev2 grammar rules."""

    # Date and time tests
    @pytest.mark.parametrize(
        "src",
        [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ],
    )
    def test_date_month(self, src: str) -> None:
        """Test date-month rule for valid month abbreviations."""
        rfc9051.Rule("date-month").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "01", "31"])
    def test_date_day(self, src: str) -> None:
        """Test date-day rule for day numbers."""
        rfc9051.Rule("date-day").parse_all(src)

    @pytest.mark.parametrize("src", [" 1", "01", "31"])
    def test_date_day_fixed(self, src: str) -> None:
        """Test date-day-fixed rule for fixed-width day numbers."""
        rfc9051.Rule("date-day-fixed").parse_all(src)

    @pytest.mark.parametrize("src", ["2021", "1997", "2024"])
    def test_date_year(self, src: str) -> None:
        """Test date-year rule for 4-digit years."""
        rfc9051.Rule("date-year").parse_all(src)

    @pytest.mark.parametrize(
        "src", ["1-Jan-2021", "31-Dec-1997", "15-Jul-2024"]
    )
    def test_date_text(self, src: str) -> None:
        """Test date-text rule for date strings."""
        rfc9051.Rule("date-text").parse_all(src)

    @pytest.mark.parametrize("src", ["12:34:56", "00:00:00", "23:59:59"])
    def test_time(self, src: str) -> None:
        """Test time rule for HH:MM:SS format."""
        rfc9051.Rule("time").parse_all(src)

    @pytest.mark.parametrize("src", ["+0000", "-0500", "+1200", "-0800"])
    def test_zone(self, src: str) -> None:
        """Test zone rule for timezone offsets."""
        rfc9051.Rule("zone").parse_all(src)

    @pytest.mark.parametrize(
        "src", ['"01-Jan-2021 12:34:56 +0000"', '" 1-Dec-1997 09:55:06 -0600"']
    )
    def test_date_time(self, src: str) -> None:
        """Test date-time rule for complete date-time strings."""
        rfc9051.Rule("date-time").parse_all(src)

    # Base64 encoding tests
    @pytest.mark.parametrize("src", ["A", "Z", "a", "z", "0", "9", "+", "/"])
    def test_base64_char(self, src: str) -> None:
        """Test base64-char rule for valid base64 characters."""
        rfc9051.Rule("base64-char").parse_all(src)

    @pytest.mark.parametrize("src", ["AA==", "ABC="])
    def test_base64_terminal(self, src: str) -> None:
        """Test base64-terminal rule for base64 padding."""
        rfc9051.Rule("base64-terminal").parse_all(src)

    @pytest.mark.parametrize("src", ["", "ABCD", "ABCDEFGH", "AA==", "ABC="])
    def test_base64(self, src: str) -> None:
        """Test base64 rule for valid base64 strings."""
        rfc9051.Rule("base64").parse_all(src)

    # Flag tests
    @pytest.mark.parametrize(
        "src", ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"]
    )
    def test_flag_standard(self, src: str) -> None:
        """Test flag rule for standard IMAP flags."""
        rfc9051.Rule("flag").parse_all(src)

    @pytest.mark.parametrize(
        "src", ["$MDNSent", "$Forwarded", "$Junk", "$NotJunk", "$Phishing"]
    )
    def test_flag_keyword(self, src: str) -> None:
        """Test flag-keyword rule for special keywords."""
        rfc9051.Rule("flag-keyword").parse_all(src)

    @pytest.mark.parametrize("src", ["\\custom", "\\MyFlag"])
    def test_flag_extension(self, src: str) -> None:
        """Test flag-extension rule for custom flags."""
        rfc9051.Rule("flag-extension").parse_all(src)

    @pytest.mark.parametrize(
        "src", ["()", "(\\Seen)", "(\\Seen \\Answered)", "(\\Flagged $Junk)"]
    )
    def test_flag_list(self, src: str) -> None:
        """Test flag-list rule for parenthesized flag lists."""
        rfc9051.Rule("flag-list").parse_all(src)

    # Mailbox and list tests
    @pytest.mark.parametrize("src", ["INBOX", "Sent", "Drafts", "MyFolder"])
    def test_mailbox(self, src: str) -> None:
        """Test mailbox rule for mailbox names."""
        rfc9051.Rule("mailbox").parse_all(src)

    @pytest.mark.parametrize("src", ["%", "*"])
    def test_list_wildcards(self, src: str) -> None:
        """Test list-wildcards rule for wildcard characters."""
        rfc9051.Rule("list-wildcards").parse_all(src)

    # Child mailbox flags
    @pytest.mark.parametrize("src", ["\\HasChildren", "\\HasNoChildren"])
    def test_child_mbox_flag(self, src: str) -> None:
        """Test child-mbox-flag rule for child mailbox indicators."""
        rfc9051.Rule("child-mbox-flag").parse_all(src)

    # Sequence and UID tests
    @pytest.mark.parametrize("src", ["1", "*"])
    def test_seq_number(self, src: str) -> None:
        """Test seq-number rule for sequence numbers."""
        rfc9051.Rule("seq-number").parse_all(src)

    @pytest.mark.parametrize("src", ["1:5", "*:*", "1:*"])
    def test_seq_range(self, src: str) -> None:
        """Test seq-range rule for sequence ranges."""
        rfc9051.Rule("seq-range").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "1:5", "1,3,5", "1:5,7:9", "$"])
    def test_sequence_set(self, src: str) -> None:
        """Test sequence-set rule for sequence sets."""
        rfc9051.Rule("sequence-set").parse_all(src)

    def test_seq_last_command(self) -> None:
        """Test seq-last-command rule for $ marker."""
        rfc9051.Rule("seq-last-command").parse_all("$")

    @pytest.mark.parametrize("src", ["1", "12", "999"])
    def test_uniqueid(self, src: str) -> None:
        """Test uniqueid rule for unique identifiers."""
        rfc9051.Rule("uniqueid").parse_all(src)

    @pytest.mark.parametrize("src", ["1:5", "100:200"])
    def test_uid_range(self, src: str) -> None:
        """Test uid-range rule for UID ranges."""
        rfc9051.Rule("uid-range").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "1:5", "1,3,5"])
    def test_uid_set(self, src: str) -> None:
        """Test uid-set rule for UID sets."""
        rfc9051.Rule("uid-set").parse_all(src)

    # Media type tests
    @pytest.mark.parametrize(
        "src",
        [
            '"APPLICATION"',
            '"AUDIO"',
            '"IMAGE"',
            '"FONT"',
            '"MESSAGE"',
            '"MODEL"',
            '"VIDEO"',
        ],
    )
    def test_media_basic_types(self, src: str) -> None:
        """Test media-basic rule for basic media types."""
        rfc9051.Rule("media-basic").parse_all(f'{src} "plain"')

    def test_media_message(self) -> None:
        """Test media-message rule for MESSAGE media type."""
        rfc9051.Rule("media-message").parse_all('"MESSAGE" "RFC822"')
        rfc9051.Rule("media-message").parse_all('"MESSAGE" "GLOBAL"')

    def test_media_text(self) -> None:
        """Test media-text rule for TEXT media type."""
        rfc9051.Rule("media-text").parse_all('"TEXT" "plain"')

    # Capability tests
    @pytest.mark.parametrize("src", ["IMAP4rev1", "STARTTLS", "AUTH=PLAIN"])
    def test_capability(self, src: str) -> None:
        """Test capability rule for server capabilities."""
        rfc9051.Rule("capability").parse_all(src)

    def test_capability_data(self) -> None:
        """Test capability-data rule for capability responses."""
        rfc9051.Rule("capability-data").parse_all("CAPABILITY IMAP4rev2")
        capability_string = "CAPABILITY STARTTLS IMAP4rev2 AUTH=PLAIN"
        rfc9051.Rule("capability-data").parse_all(capability_string)

    # Command tests - basic structure
    @pytest.mark.parametrize("src", ["CAPABILITY", "LOGOUT", "NOOP"])
    def test_command_any(self, src: str) -> None:
        """Test command-any rule for any-state commands."""
        rfc9051.Rule("command-any").parse_all(src)

    @pytest.mark.parametrize("src", ["STARTTLS"])
    def test_command_nonauth(self, src: str) -> None:
        """Test command-nonauth rule for non-authenticated commands."""
        rfc9051.Rule("command-nonauth").parse_all(src)

    @pytest.mark.parametrize("src", ["CLOSE", "UNSELECT", "EXPUNGE"])
    def test_command_select(self, src: str) -> None:
        """Test command-select rule for selected-state commands."""
        rfc9051.Rule("command-select").parse_all(src)

    # Simple command tests
    def test_create_command(self) -> None:
        """Test CREATE command structure."""
        rfc9051.Rule("create").parse_all("CREATE TestFolder")

    def test_delete_command(self) -> None:
        """Test DELETE command structure."""
        rfc9051.Rule("delete").parse_all("DELETE TestFolder")

    def test_select_command(self) -> None:
        """Test SELECT command structure."""
        rfc9051.Rule("select").parse_all("SELECT INBOX")

    def test_examine_command(self) -> None:
        """Test EXAMINE command structure."""
        rfc9051.Rule("examine").parse_all("EXAMINE INBOX")

    def test_subscribe_command(self) -> None:
        """Test SUBSCRIBE command structure."""
        rfc9051.Rule("subscribe").parse_all("SUBSCRIBE TestFolder")

    def test_unsubscribe_command(self) -> None:
        """Test UNSUBSCRIBE command structure."""
        rfc9051.Rule("unsubscribe").parse_all("UNSUBSCRIBE TestFolder")

    def test_namespace_command(self) -> None:
        """Test NAMESPACE command structure."""
        rfc9051.Rule("namespace-command").parse_all("NAMESPACE")

    # Response condition tests
    @pytest.mark.parametrize("src", ["OK", "NO", "BAD"])
    def test_resp_cond_state(self, src: str) -> None:
        """Test resp-cond-state rule for response conditions."""
        rfc9051.Rule("resp-cond-state").parse_all(f"{src} Command completed")

    @pytest.mark.parametrize("src", ["OK", "PREAUTH"])
    def test_resp_cond_auth(self, src: str) -> None:
        """Test resp-cond-auth rule for authentication responses."""
        rfc9051.Rule("resp-cond-auth").parse_all(f"{src} Server ready")

    def test_resp_cond_bye(self) -> None:
        """Test resp-cond-bye rule for BYE responses."""
        bye_message = "BYE Server closing connection"
        rfc9051.Rule("resp-cond-bye").parse_all(bye_message)

    # Status attribute tests
    @pytest.mark.parametrize(
        "src",
        ["MESSAGES", "UIDNEXT", "UIDVALIDITY", "UNSEEN", "DELETED", "SIZE"],
    )
    def test_status_att(self, src: str) -> None:
        """Test status-att rule for status attributes."""
        rfc9051.Rule("status-att").parse_all(src)

    @pytest.mark.parametrize("src", ["MESSAGES 5", "UIDNEXT 123", "SIZE 1024"])
    def test_status_att_val(self, src: str) -> None:
        """Test status-att-val rule for status attribute values."""
        rfc9051.Rule("status-att-val").parse_all(src)

    # Search key tests
    @pytest.mark.parametrize(
        "src",
        [
            "ALL",
            "ANSWERED",
            "DELETED",
            "FLAGGED",
            "SEEN",
            "DRAFT",
            "UNANSWERED",
            "UNDELETED",
            "UNFLAGGED",
            "UNSEEN",
            "UNDRAFT",
        ],
    )
    def test_search_key_simple(self, src: str) -> None:
        """Test search-key rule for simple search criteria."""
        rfc9051.Rule("search-key").parse_all(src)

    @pytest.mark.parametrize(
        "src",
        [
            "BCC test@example.com",
            "FROM sender@test.com",
            "TO recipient@example.org",
        ],
    )
    def test_search_key_with_astring(self, src: str) -> None:
        """Test search-key rule for search criteria with astring."""
        rfc9051.Rule("search-key").parse_all(src)

    # Section tests
    @pytest.mark.parametrize(
        "src", ["[]", "[1]", "[1.2]", "[HEADER]", "[TEXT]"]
    )
    def test_section(self, src: str) -> None:
        """Test section rule for message sections."""
        rfc9051.Rule("section").parse_all(src)

    @pytest.mark.parametrize("src", ["HEADER", "TEXT", "MIME"])
    def test_section_text(self, src: str) -> None:
        """Test section-text rule for section text types."""
        rfc9051.Rule("section-text").parse_all(src)

    @pytest.mark.parametrize("src", ["1", "1.2", "1.2.3"])
    def test_section_part(self, src: str) -> None:
        """Test section-part rule for message part numbers."""
        rfc9051.Rule("section-part").parse_all(src)

    # Fetch attribute tests
    @pytest.mark.parametrize(
        "src",
        ["ENVELOPE", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "BODY", "UID"],
    )
    def test_fetch_att_simple(self, src: str) -> None:
        """Test fetch-att rule for simple fetch attributes."""
        rfc9051.Rule("fetch-att").parse_all(src)

    # Tagged extension tests
    @pytest.mark.parametrize("src", ["test-label", "my_extension", "ext.name"])
    def test_tagged_ext_label(self, src: str) -> None:
        """Test tagged-ext-label rule for extension labels."""
        rfc9051.Rule("tagged-ext-label").parse_all(src)

    # Vendor token tests
    def test_vendor_token(self) -> None:
        """Test vendor-token rule for vendor-specific extensions."""
        rfc9051.Rule("vendor-token").parse_all("vendor.example")

    # Obsolete rules tests
    def test_obsolete_flag_recent(self) -> None:
        """Test obsolete-flag-recent rule."""
        rfc9051.Rule("obsolete-flag-recent").parse_all("\\Recent")

    @pytest.mark.parametrize("src", ["5 RECENT", "0 RECENT"])
    def test_obsolete_recent_response(self, src: str) -> None:
        """Test obsolete-recent-response rule."""
        rfc9051.Rule("obsolete-recent-response").parse_all(src)

    def test_obsolete_search_response(self) -> None:
        """Test obsolete-search-response rule."""
        rfc9051.Rule("obsolete-search-response").parse_all("SEARCH")
        rfc9051.Rule("obsolete-search-response").parse_all("SEARCH 1 2 3")

    # More complex rule tests
    def test_address_structure(self) -> None:
        """Test address rule for email address structure in IMAP format."""
        address = '("John Doe" NIL "john" "example.com")'
        rfc9051.Rule("address").parse_all(address)

        # Test with NIL name
        address_nil = '(NIL NIL "user" "domain.org")'
        rfc9051.Rule("address").parse_all(address_nil)

    @pytest.mark.parametrize("src", ["NIL", '"test"', '"hello world"'])
    def test_addr_name(self, src: str) -> None:
        """Test addr-name rule for address name part."""
        rfc9051.Rule("addr-name").parse_all(src)

    @pytest.mark.parametrize("src", ["NIL", '"test"', '"hello world"'])
    def test_addr_adl(self, src: str) -> None:
        """Test addr-adl rule for address adl part."""
        rfc9051.Rule("addr-adl").parse_all(src)

    @pytest.mark.parametrize("src", ["NIL", '"user"', '"mailbox"'])
    def test_addr_mailbox(self, src: str) -> None:
        """Test addr-mailbox rule for address mailbox part."""
        rfc9051.Rule("addr-mailbox").parse_all(src)

    @pytest.mark.parametrize("src", ["NIL", '"example.com"', '"domain.org"'])
    def test_addr_host(self, src: str) -> None:
        """Test addr-host rule for address host part."""
        rfc9051.Rule("addr-host").parse_all(src)

    # Envelope tests
    def test_envelope_simple(self) -> None:
        """Test envelope rule for message envelope structure."""
        envelope_data = (
            '("Wed, 17 Jul 1996 02:23:25 -0700" "Test Subject" '
            '(("John" NIL "john" "example.com")) '
            '(("John" NIL "john" "example.com")) '
            '(("John" NIL "john" "example.com")) '
            '(("Jane" NIL "jane" "example.org")) '
            'NIL NIL NIL "<test@example.com>")'
        )
        rfc9051.Rule("envelope").parse_all(envelope_data)

    @pytest.mark.parametrize(
        "src", ["NIL", '"test@example.com"', '"<message-id@host.com>"']
    )
    def test_env_message_id(self, src: str) -> None:
        """Test env-message-id rule for message IDs."""
        rfc9051.Rule("env-message-id").parse_all(src)

    @pytest.mark.parametrize(
        "src", ["NIL", '"Test Subject"', '"Re: Important Message"']
    )
    def test_env_subject(self, src: str) -> None:
        """Test env-subject rule for email subjects."""
        rfc9051.Rule("env-subject").parse_all(src)

    # Body structure tests
    def test_body_fld_param_nil(self) -> None:
        """Test body-fld-param rule with NIL."""
        rfc9051.Rule("body-fld-param").parse_all("NIL")

    def test_body_fld_param_with_params(self) -> None:
        """Test body-fld-param rule with parameters."""
        params = '("CHARSET" "US-ASCII" "BOUNDARY" "boundary123")'
        rfc9051.Rule("body-fld-param").parse_all(params)

    @pytest.mark.parametrize(
        "src",
        ['"7BIT"', '"8BIT"', '"BINARY"', '"BASE64"', '"QUOTED-PRINTABLE"'],
    )
    def test_body_fld_enc(self, src: str) -> None:
        """Test body-fld-enc rule for content encodings."""
        rfc9051.Rule("body-fld-enc").parse_all(src)

    # Literal tests
    def test_literal_basic(self) -> None:
        """Test literal rule for basic literal format."""
        literal_str = "{5}\r\nhello"
        rfc9051.Rule("literal").parse_all(literal_str)

    def test_literal_with_plus(self) -> None:
        """Test literal rule with non-sync literal."""
        literal_str = "{5+}\r\nhello"
        rfc9051.Rule("literal").parse_all(literal_str)

    def test_literal8_basic(self) -> None:
        """Test literal8 rule for 8-bit literal format."""
        literal_str = "~{5}\r\nhello"
        rfc9051.Rule("literal8").parse_all(literal_str)

    # Authentication tests
    def test_auth_type(self) -> None:
        """Test auth-type rule for authentication mechanisms."""
        rfc9051.Rule("auth-type").parse_all("PLAIN")
        rfc9051.Rule("auth-type").parse_all("CRAM-MD5")

    def test_initial_resp(self) -> None:
        """Test initial-resp rule for authentication responses."""
        rfc9051.Rule("initial-resp").parse_all("=")
        rfc9051.Rule("initial-resp").parse_all("dGVzdA==")

    # Login tests
    def test_login_command(self) -> None:
        """Test login command structure."""
        rfc9051.Rule("login").parse_all("LOGIN testuser testpass")

    @pytest.mark.parametrize("src", ["testuser", '"test user"'])
    def test_userid(self, src: str) -> None:
        """Test userid rule for user identifiers."""
        rfc9051.Rule("userid").parse_all(src)

    @pytest.mark.parametrize("src", ["password", '"pass word"'])
    def test_password(self, src: str) -> None:
        """Test password rule for passwords."""
        rfc9051.Rule("password").parse_all(src)

    # Append command tests
    def test_append_simple(self) -> None:
        """Test append command without optional parts."""
        append_cmd = "APPEND INBOX {5}\r\nhello"
        rfc9051.Rule("append").parse_all(append_cmd)

    def test_append_with_flags(self) -> None:
        """Test append command with flags."""
        append_cmd = "APPEND INBOX (\\Seen) {5}\r\nhello"
        rfc9051.Rule("append").parse_all(append_cmd)

    def test_append_with_datetime(self) -> None:
        """Test append command with date-time."""
        append_cmd = 'APPEND INBOX "17-Jul-1996 02:23:25 -0700" {5}\r\nhello'
        rfc9051.Rule("append").parse_all(append_cmd)

    def test_append_full(self) -> None:
        """Test append command with all optional parts."""
        append_cmd = (
            "APPEND INBOX (\\Seen \\Flagged) "
            '"17-Jul-1996 02:23:25 -0700" {5}\r\nhello'
        )
        rfc9051.Rule("append").parse_all(append_cmd)

    # Copy and Move commands
    def test_copy_command(self) -> None:
        """Test COPY command structure."""
        rfc9051.Rule("copy").parse_all("COPY 1:5 DestFolder")

    def test_move_command(self) -> None:
        """Test MOVE command structure."""
        rfc9051.Rule("move").parse_all("MOVE 1:5 DestFolder")

    # Store command tests
    def test_store_flags(self) -> None:
        """Test STORE command with FLAGS."""
        rfc9051.Rule("store").parse_all("STORE 1:5 FLAGS (\\Seen)")

    def test_store_flags_silent(self) -> None:
        """Test STORE command with FLAGS.SILENT."""
        rfc9051.Rule("store").parse_all("STORE 1:5 FLAGS.SILENT (\\Seen)")

    def test_store_plus_flags(self) -> None:
        """Test STORE command with +FLAGS."""
        rfc9051.Rule("store").parse_all("STORE 1:5 +FLAGS (\\Flagged)")

    def test_store_minus_flags(self) -> None:
        """Test STORE command with -FLAGS."""
        rfc9051.Rule("store").parse_all("STORE 1:5 -FLAGS (\\Deleted)")

    # Search command tests
    def test_search_simple(self) -> None:
        """Test simple SEARCH command."""
        rfc9051.Rule("search").parse_all("SEARCH ALL")

    def test_search_with_charset(self) -> None:
        """Test SEARCH command with charset specification."""
        rfc9051.Rule("search").parse_all("SEARCH CHARSET UTF-8 ALL")

    def test_search_complex(self) -> None:
        """Test complex SEARCH command."""
        search_cmd = "SEARCH FROM test@example.com SUBJECT hello"
        rfc9051.Rule("search").parse_all(search_cmd)

    def test_search_with_return(self) -> None:
        """Test SEARCH command with RETURN options."""
        search_cmd = "SEARCH RETURN (MIN MAX COUNT) ALL"
        rfc9051.Rule("search").parse_all(search_cmd)

    # Fetch command tests
    def test_fetch_all(self) -> None:
        """Test FETCH command with ALL."""
        rfc9051.Rule("fetch").parse_all("FETCH 1:5 ALL")

    def test_fetch_full(self) -> None:
        """Test FETCH command with FULL."""
        rfc9051.Rule("fetch").parse_all("FETCH 1:5 FULL")

    def test_fetch_fast(self) -> None:
        """Test FETCH command with FAST."""
        rfc9051.Rule("fetch").parse_all("FETCH 1:5 FAST")

    def test_fetch_single_att(self) -> None:
        """Test FETCH command with single attribute."""
        rfc9051.Rule("fetch").parse_all("FETCH 1:5 ENVELOPE")

    def test_fetch_multiple_att(self) -> None:
        """Test FETCH command with multiple attributes."""
        fetch_cmd = "FETCH 1:5 (ENVELOPE FLAGS INTERNALDATE)"
        rfc9051.Rule("fetch").parse_all(fetch_cmd)

    def test_fetch_body_section(self) -> None:
        """Test FETCH command with BODY section."""
        rfc9051.Rule("fetch").parse_all("FETCH 1 BODY[HEADER]")

    def test_fetch_body_peek(self) -> None:
        """Test FETCH command with BODY.PEEK."""
        rfc9051.Rule("fetch").parse_all("FETCH 1 BODY.PEEK[TEXT]")

    # UID command tests
    def test_uid_fetch(self) -> None:
        """Test UID FETCH command."""
        rfc9051.Rule("uid").parse_all("UID FETCH 100:200 ENVELOPE")

    def test_uid_search(self) -> None:
        """Test UID SEARCH command."""
        rfc9051.Rule("uid").parse_all("UID SEARCH ALL")

    def test_uid_store(self) -> None:
        """Test UID STORE command."""
        rfc9051.Rule("uid").parse_all("UID STORE 100:200 +FLAGS (\\Seen)")

    def test_uid_copy(self) -> None:
        """Test UID COPY command."""
        rfc9051.Rule("uid").parse_all("UID COPY 100:200 DestFolder")

    def test_uid_move(self) -> None:
        """Test UID MOVE command."""
        rfc9051.Rule("uid").parse_all("UID MOVE 100:200 DestFolder")

    def test_uid_expunge(self) -> None:
        """Test UID EXPUNGE command."""
        rfc9051.Rule("uid-expunge").parse_all("EXPUNGE 100:200")

    # List command tests
    def test_list_simple(self) -> None:
        """Test simple LIST command."""
        rfc9051.Rule("list").parse_all('LIST "" "*"')

    def test_list_with_reference(self) -> None:
        """Test LIST command with reference."""
        rfc9051.Rule("list").parse_all('LIST "INBOX" "*"')

    def test_list_with_pattern(self) -> None:
        """Test LIST command with pattern."""
        rfc9051.Rule("list").parse_all('LIST "" "INBOX.*"')

    def test_list_with_select_opts(self) -> None:
        """Test LIST command with selection options."""
        list_cmd = 'LIST (SUBSCRIBED) "" "*"'
        rfc9051.Rule("list").parse_all(list_cmd)

    def test_list_with_return_opts(self) -> None:
        """Test LIST command with return options."""
        list_cmd = 'LIST "" "*" RETURN (SUBSCRIBED CHILDREN)'
        rfc9051.Rule("list").parse_all(list_cmd)

    # Status command tests
    def test_status_command(self) -> None:
        """Test STATUS command structure."""
        status_cmd = "STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN)"
        rfc9051.Rule("status").parse_all(status_cmd)

    # Enable command tests
    def test_enable_command(self) -> None:
        """Test ENABLE command structure."""
        rfc9051.Rule("enable").parse_all("ENABLE CONDSTORE")
        rfc9051.Rule("enable").parse_all("ENABLE QRESYNC CONDSTORE")

    # IDLE command tests
    def test_idle_command(self) -> None:
        """Test IDLE command structure."""
        rfc9051.Rule("idle").parse_all("IDLE\r\nDONE")

    # Rename command tests
    def test_rename_command(self) -> None:
        """Test RENAME command structure."""
        rfc9051.Rule("rename").parse_all("RENAME OldName NewName")

    # Message attribute tests
    @pytest.mark.parametrize("src", ["1 EXPUNGE", "5 FETCH (FLAGS (\\Seen))"])
    def test_message_data(self, src: str) -> None:
        """Test message-data rule for server responses."""
        rfc9051.Rule("message-data").parse_all(src)

    # Response tests
    def test_continue_req(self) -> None:
        """Test continue-req rule for command continuation."""
        continue_msg = "+ Ready for additional data\r\n"
        rfc9051.Rule("continue-req").parse_all(continue_msg)
        rfc9051.Rule("continue-req").parse_all("+ \r\n")

    # Mailbox list tests
    def test_mailbox_list_simple(self) -> None:
        """Test mailbox-list rule for simple mailbox listing."""
        mbx_list = '(\\HasNoChildren) "." "INBOX"'
        rfc9051.Rule("mailbox-list").parse_all(mbx_list)

    def test_mailbox_list_with_nil_delimiter(self) -> None:
        """Test mailbox-list rule with NIL delimiter."""
        mbx_list = '(\\Noselect) NIL "Folder"'
        rfc9051.Rule("mailbox-list").parse_all(mbx_list)

    # Namespace tests
    def test_namespace_nil(self) -> None:
        """Test namespace rule with NIL."""
        rfc9051.Rule("namespace").parse_all("NIL")

    def test_namespace_with_descr(self) -> None:
        """Test namespace rule with namespace description."""
        namespace_data = '(("" "."))'
        rfc9051.Rule("namespace").parse_all(namespace_data)

    def test_namespace_response(self) -> None:
        """Test namespace-response rule for NAMESPACE responses."""
        namespace_resp = 'NAMESPACE (("" ".")) NIL NIL'
        rfc9051.Rule("namespace-response").parse_all(namespace_resp)

    # Tag tests
    @pytest.mark.parametrize("src", ["A001", "tag123", "CMD"])
    def test_tag(self, src: str) -> None:
        """Test tag rule for command tags."""
        rfc9051.Rule("tag").parse_all(src)

    @pytest.mark.parametrize("src", ["+"])
    def test_tag_invalid(self, src: str) -> None:
        """Test tag rule fails for invalid tags."""
        with pytest.raises(ParseError):
            rfc9051.Rule("tag").parse_all(src)

    # Response code tests
    @pytest.mark.parametrize(
        "src", ["APPENDUID 123 456", "COPYUID 123 1:5 100:104"]
    )
    def test_response_codes(self, src: str) -> None:
        """Test various response codes."""
        if src.startswith("APPENDUID"):
            rfc9051.Rule("resp-code-apnd").parse_all(src)
        elif src.startswith("COPYUID"):
            rfc9051.Rule("resp-code-copy").parse_all(src)

    # Charset tests
    @pytest.mark.parametrize("src", ["UTF-8", "US-ASCII", '"UTF-8"'])
    def test_charset(self, src: str) -> None:
        """Test charset rule for character set specifications."""
        rfc9051.Rule("charset").parse_all(src)

    # Partial range tests
    @pytest.mark.parametrize("src", ["100", "100.200"])
    def test_partial_range(self, src: str) -> None:
        """Test partial-range rule for partial fetch ranges."""
        rfc9051.Rule("partial-range").parse_all(src)

    def test_partial(self) -> None:
        """Test partial rule for partial fetch specification."""
        rfc9051.Rule("partial").parse_all("<100.200>")

    # Patterns tests
    def test_patterns(self) -> None:
        """Test patterns rule for LIST patterns."""
        rfc9051.Rule("patterns").parse_all('("INBOX.*")')

    # Additional complex tests
    def test_full_command_structure(self) -> None:
        """Test complete command structure with tag and CRLF."""
        command = "A001 SELECT INBOX\r\n"
        rfc9051.Rule("command").parse_all(command)

    def test_greeting_ok(self) -> None:
        """Test greeting rule for server greeting."""
        greeting = "* OK IMAP4rev2 Server ready\r\n"
        rfc9051.Rule("greeting").parse_all(greeting)

    def test_greeting_preauth(self) -> None:
        """Test greeting rule for pre-authenticated connection."""
        greeting = "* PREAUTH Welcome, already authenticated\r\n"
        rfc9051.Rule("greeting").parse_all(greeting)

    def test_response_tagged(self) -> None:
        """Test response-tagged rule for tagged responses."""
        response = "A001 OK Command completed\r\n"
        rfc9051.Rule("response-tagged").parse_all(response)

    def test_response_data(self) -> None:
        """Test response-data rule for untagged responses."""
        response = "* 5 EXISTS\r\n"
        rfc9051.Rule("response-data").parse_all(response)

    # Header field tests
    @pytest.mark.parametrize("src", ["Subject", "From", "To", "Date"])
    def test_header_fld_name(self, src: str) -> None:
        """Test header-fld-name rule for header field names."""
        rfc9051.Rule("header-fld-name").parse_all(src)

    def test_header_list(self) -> None:
        """Test header-list rule for header field lists."""
        rfc9051.Rule("header-list").parse_all("(Subject From Date)")

    # ESEARCH response tests
    def test_esearch_response_simple(self) -> None:
        """Test esearch-response rule for extended search responses."""
        rfc9051.Rule("esearch-response").parse_all("ESEARCH UID MIN 1 MAX 100")

    def test_esearch_response_with_tag(self) -> None:
        """Test esearch-response with search correlator."""
        response = 'ESEARCH (TAG "A001") UID ALL 1:5,10:15'
        rfc9051.Rule("esearch-response").parse_all(response)
