"""
Structured Field Values for HTTP.

Collected rules from RFC 9651
https://www.rfc-editor.org/rfc/rfc9651

RFC 9651 obsoletes RFC 8941, adding the Date (``@``) and Display String
(``%"..."``) types.

This module provides two layers:

* ``Rule`` -- an ABNF grammar (RFC 9651, Appendix C) for the three top-level
  types (``sf-list``, ``sf-dictionary``, ``sf-item``), consistent with the
  other grammar modules.  Use it to obtain parse trees.

* :func:`parse_item`, :func:`parse_list`, :func:`parse_dictionary` -- parsers
  that implement the step-by-step algorithms in RFC 9651, Section 4.2, and
  return the typed abstract data model (:class:`Item`, :class:`InnerList`,
  :class:`Dictionary`, :class:`List` with typed bare values).

The Appendix C ABNF is explicitly non-normative: "If there is disagreement
between the parsing algorithms and ABNF, the specified algorithms take
precedence."  A few requirements cannot be expressed in ABNF and live only in
the algorithms -- duplicate Dictionary/parameter keys resolve to the last
value, Byte Sequences must base64-decode, Display Strings must be valid UTF-8
after percent-decoding, and leading/trailing bare spaces are stripped at the
field top level.  The parse functions therefore follow Section 4.2 directly
rather than the grammar.
"""

import base64 as _base64
import binascii as _binascii
import decimal as _decimal
import string as _string
from typing import ClassVar, NoReturn

from abnf.parser import Rule as _Rule

from . import rfc9110
from .misc import load_grammar_rulelist

__all__ = [
    "Date",
    "Decimal",
    "Dictionary",
    "DisplayString",
    "InnerList",
    "Integer",
    "Item",
    "List",
    "Parameters",
    "Rule",
    "String",
    "StructuredFieldError",
    "Token",
    "parse_dictionary",
    "parse_item",
    "parse_list",
]


# ---------------------------------------------------------------------------
# Layer 1: grammar (RFC 9651, Appendix C)
# ---------------------------------------------------------------------------


@load_grammar_rulelist(
    [
        ("tchar", rfc9110.Rule("tchar")),
        ("OWS", rfc9110.Rule("OWS")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 9651, Appendix C."""

    grammar: ClassVar[
        list[str] | str
    ] = r"""sf-list = list-member *( OWS "," OWS list-member )
list-member = sf-item / inner-list
inner-list = "(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")" parameters
parameters = *( ";" *SP parameter )
parameter = param-key [ "=" param-value ]
param-key = key
key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
lcalpha = %x61-7A
param-value = bare-item
sf-dictionary = dict-member *( OWS "," OWS dict-member )
dict-member = member-key ( parameters / ( "=" member-value ) )
member-key = key
member-value = sf-item / inner-list
sf-item = bare-item parameters
bare-item = sf-integer / sf-decimal / sf-string / sf-token / sf-binary / sf-boolean / sf-date / sf-displaystring
sf-integer = ["-"] 1*15DIGIT
sf-decimal = ["-"] 1*12DIGIT "." 1*3DIGIT
sf-string = DQUOTE *( unescaped / "%" / bs-escaped ) DQUOTE
sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" )
sf-binary = ":" base64 ":"
sf-boolean = "?" ( "0" / "1" )
sf-date = "@" sf-integer
sf-displaystring = "%" DQUOTE *( unescaped / "\" / pct-encoded ) DQUOTE
base64 = *( ALPHA / DIGIT / "+" / "/" ) *"="
unescaped = %x20-21 / %x23-24 / %x26-5B / %x5D-7E
bs-escaped = "\" ( DQUOTE / "\" )
pct-encoded = "%" lc-hexdig lc-hexdig
lc-hexdig = DIGIT / %x61-66
"""


# ---------------------------------------------------------------------------
# Layer 2: typed abstract data model (RFC 9651, Section 3)
# ---------------------------------------------------------------------------


class Integer(int):
    """An Integer (RFC 9651, Section 3.3.1)."""

    __slots__ = ()


class Decimal(_decimal.Decimal):
    """A Decimal (RFC 9651, Section 3.3.2)."""

    __slots__ = ()


class String(str):
    """A String (RFC 9651, Section 3.3.3)."""

    __slots__ = ()


class Token(str):
    """A Token (RFC 9651, Section 3.3.4)."""

    __slots__ = ()


class DisplayString(str):
    """A Display String (RFC 9651, Section 3.3.8)."""

    __slots__ = ()


class Date(int):
    """A Date, as a number of seconds relative to the Unix epoch
    (RFC 9651, Section 3.3.7)."""

    __slots__ = ()


# Byte Sequences (Section 3.3.5) are represented as ``bytes`` and Booleans
# (Section 3.3.6) as ``bool``; both are used directly.

BareItem = Integer | Decimal | String | Token | DisplayString | Date | bytes | bool


class Parameters(dict):
    """An ordered map of parameters keyed by name, with bare-item values
    (RFC 9651, Section 3.1.2).  Duplicate keys resolve to the last value."""

    __slots__ = ()


class Item:
    """A bare item together with its parameters (RFC 9651, Section 3.3)."""

    __slots__ = ("params", "value")

    def __init__(self, value: BareItem, params: "Parameters | None" = None):
        self.value = value
        self.params = params if params is not None else Parameters()

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Item)
            and self.value == other.value
            and self.params == other.params
        )

    def __hash__(self) -> int:  # pragma: no cover - Items are mutable containers
        msg = "Item is unhashable"
        raise TypeError(msg)

    def __repr__(self) -> str:
        return f"Item({self.value!r}, {self.params!r})"


class InnerList:
    """An array of items together with its parameters
    (RFC 9651, Section 3.1.1)."""

    __slots__ = ("items", "params")

    def __init__(
        self,
        items: "list[Item] | None" = None,
        params: "Parameters | None" = None,
    ):
        self.items = list(items) if items is not None else []
        self.params = params if params is not None else Parameters()

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, InnerList)
            and self.items == other.items
            and self.params == other.params
        )

    def __hash__(self) -> int:  # pragma: no cover - InnerLists are mutable
        msg = "InnerList is unhashable"
        raise TypeError(msg)

    def __repr__(self) -> str:
        return f"InnerList({self.items!r}, {self.params!r})"


class Dictionary(dict):
    """An ordered map of Item or InnerList values keyed by name
    (RFC 9651, Section 3.2).  Duplicate keys resolve to the last value."""

    __slots__ = ()


class List(list):
    """An array of Item or InnerList members (RFC 9651, Section 3.1)."""

    __slots__ = ()


# ---------------------------------------------------------------------------
# Layer 2: parsers (RFC 9651, Section 4.2)
# ---------------------------------------------------------------------------


class StructuredFieldError(ValueError):
    """Raised when a value fails to parse per RFC 9651, Section 4.2."""


def _fail(message: str) -> NoReturn:
    raise StructuredFieldError(message)


_DIGITS = frozenset(_string.digits)
_ALPHA = frozenset(_string.ascii_letters)
_LCALPHA = frozenset(_string.ascii_lowercase)
_LC_HEXDIG = frozenset(_string.digits + "abcdef")
_KEY_CHARS = frozenset(_string.ascii_lowercase + _string.digits + "_-.*")
_TCHAR = frozenset("!#$%&'*+-.^_`|~" + _string.digits + _string.ascii_letters)
_TOKEN_CHARS = _TCHAR | {":", "/"}
_B64_CHARS = frozenset(_string.ascii_letters + _string.digits + "+/=")
_SP = frozenset(" ")
_OWS = frozenset(" \t")


class _Input:
    """A forward cursor over an ASCII string, mirroring the "input_string is
    modified to remove the parsed value" convention in RFC 9651, Section 4.2.

    Consumption happens only through :meth:`take` and its helpers; callers
    never index into the underlying string or move the cursor directly."""

    __slots__ = ("pos", "s")

    def __init__(self, s: str):
        self.s = s
        self.pos = 0

    @property
    def empty(self) -> bool:
        return self.pos >= len(self.s)

    def peek(self) -> str:
        """The next character, or "" at end of input."""
        return self.s[self.pos] if self.pos < len(self.s) else ""

    def take(self, n: int = 1) -> str:
        """Consume and return the next ``n`` characters (fewer at end of
        input, "" once exhausted)."""
        end = min(self.pos + n, len(self.s))
        chunk = self.s[self.pos : end]
        self.pos = end
        return chunk

    def take_while(self, allowed: frozenset[str]) -> str:
        """Consume and return the leading run of characters found in
        ``allowed``."""
        end = self.pos
        while end < len(self.s) and self.s[end] in allowed:
            end += 1
        return self.take(end - self.pos)

    def take_until(self, char: str) -> str | None:
        """Consume up to (but not including) the next ``char`` and return the
        skipped text, or None if ``char`` is not in the remaining input."""
        end = self.s.find(char, self.pos)
        if end == -1:
            return None
        return self.take(end - self.pos)

    def discard_sp(self) -> None:
        self.take_while(_SP)

    def discard_ows(self) -> None:
        self.take_while(_OWS)


def parse_item(field_value: str) -> Item:
    """Parse a field value as an Item (RFC 9651, Sections 4.2, 4.2.3)."""
    return _parse_top(field_value, _parse_item)


def parse_list(field_value: str) -> List:
    """Parse a field value as a List (RFC 9651, Sections 4.2, 4.2.1)."""
    return _parse_top(field_value, _parse_list)


def parse_dictionary(field_value: str) -> Dictionary:
    """Parse a field value as a Dictionary (RFC 9651, Sections 4.2, 4.2.2)."""
    return _parse_top(field_value, _parse_dictionary)


def _parse_top(field_value, fn):
    """Parse a top-level field value (RFC 9651, Section 4.2)."""
    try:
        field_value.encode("ascii")  # step 1
    except UnicodeEncodeError as exc:
        msg = "field value contains non-ASCII characters"
        raise StructuredFieldError(msg) from exc
    inp = _Input(field_value)
    inp.discard_sp()  # step 2
    output = fn(inp)  # steps 3-5
    inp.discard_sp()  # step 6
    if not inp.empty:  # step 7
        _fail("trailing characters after structured field")
    return output  # step 8


def _parse_list(inp: _Input) -> List:
    """Parse a List (RFC 9651, Section 4.2.1)."""
    members = List()
    while not inp.empty:
        members.append(_parse_item_or_inner_list(inp))
        inp.discard_ows()
        if inp.empty:
            return members
        if inp.take() != ",":
            _fail("expected ',' between list members")
        inp.discard_ows()
        if inp.empty:
            _fail("trailing comma in list")
    return members


def _parse_item_or_inner_list(inp: _Input) -> Item | InnerList:
    """Parse an Item or Inner List (RFC 9651, Section 4.2.1.1)."""
    if inp.peek() == "(":
        return _parse_inner_list(inp)
    return _parse_item(inp)


def _parse_inner_list(inp: _Input) -> InnerList:
    """Parse an Inner List (RFC 9651, Section 4.2.1.2)."""
    if inp.take() != "(":
        _fail("expected '(' to open inner list")
    items: list[Item] = []
    while not inp.empty:
        inp.discard_sp()
        if inp.peek() == ")":
            inp.take()
            params = _parse_parameters(inp)
            return InnerList(items, params)
        items.append(_parse_item(inp))
        if inp.peek() not in (" ", ")"):
            _fail("expected ' ' or ')' in inner list")
    _fail("unterminated inner list")


def _parse_dictionary(inp: _Input) -> Dictionary:
    """Parse a Dictionary (RFC 9651, Section 4.2.2)."""
    dictionary = Dictionary()
    while not inp.empty:
        key = _parse_key(inp)
        if inp.peek() == "=":
            inp.take()
            member: Item | InnerList = _parse_item_or_inner_list(inp)
        else:
            member = Item(True, _parse_parameters(inp))
        # Assigning to an existing key overwrites the value while preserving
        # its position, matching "overwrite" / "append" in Section 4.2.2.
        dictionary[key] = member
        inp.discard_ows()
        if inp.empty:
            return dictionary
        if inp.take() != ",":
            _fail("expected ',' between dictionary members")
        inp.discard_ows()
        if inp.empty:
            _fail("trailing comma in dictionary")
    return dictionary


def _parse_item(inp: _Input) -> Item:
    """Parse an Item (RFC 9651, Section 4.2.3)."""
    bare_item = _parse_bare_item(inp)
    parameters = _parse_parameters(inp)
    return Item(bare_item, parameters)


def _parse_bare_item(inp: _Input) -> BareItem:
    """Parse a bare Item (RFC 9651, Section 4.2.3.1)."""
    c = inp.peek()
    if c == "-" or c in _DIGITS:
        return _parse_integer_or_decimal(inp)
    if c == '"':
        return _parse_string(inp)
    if c in _ALPHA or c == "*":
        return _parse_token(inp)
    if c == ":":
        return _parse_byte_sequence(inp)
    if c == "?":
        return _parse_boolean(inp)
    if c == "@":
        return _parse_date(inp)
    if c == "%":
        return _parse_display_string(inp)
    _fail("unrecognized bare item")


def _parse_parameters(inp: _Input) -> Parameters:
    """Parse Parameters (RFC 9651, Section 4.2.3.2)."""
    parameters = Parameters()
    while not inp.empty:
        if inp.peek() != ";":
            break
        inp.take()  # ";"
        inp.discard_sp()
        key = _parse_key(inp)
        if inp.peek() == "=":
            inp.take()
            value: BareItem = _parse_bare_item(inp)
        else:
            value = True
        # Overwrite in place on duplicate key; see Section 4.2.3.2.
        parameters[key] = value
    return parameters


def _parse_key(inp: _Input) -> str:
    """Parse a Key (RFC 9651, Section 4.2.3.3)."""
    if not (inp.peek() in _LCALPHA or inp.peek() == "*"):
        _fail("expected key")
    return inp.take_while(_KEY_CHARS)


def _parse_integer_or_decimal(inp: _Input) -> Integer | Decimal:
    """Parse an Integer or Decimal (RFC 9651, Section 4.2.4)."""
    is_decimal = False
    sign = 1
    number: list[str] = []
    if inp.peek() == "-":
        inp.take()
        sign = -1
    if inp.empty:
        _fail("empty integer")
    if inp.peek() not in _DIGITS:
        _fail("expected digit")
    while not inp.empty:
        char = inp.peek()
        if char in _DIGITS:
            number.append(inp.take())
        elif not is_decimal and char == ".":
            if len(number) > 12:
                _fail("too many digits before decimal point")
            number.append(inp.take())
            is_decimal = True
        else:
            break  # leave the character in the input
        if not is_decimal and len(number) > 15:
            _fail("integer too long")
        if is_decimal and len(number) > 16:
            _fail("decimal too long")
    digits = "".join(number)
    if not is_decimal:
        value = int(digits)
        return Integer(-value if sign < 0 else value)
    if digits.endswith("."):
        _fail("decimal ends with '.'")
    if len(digits) - digits.index(".") - 1 > 3:
        _fail("too many digits after decimal point")
    dec = _decimal.Decimal(digits)
    return Decimal(-dec if sign < 0 else dec)


def _parse_string(inp: _Input) -> String:
    """Parse a String (RFC 9651, Section 4.2.5)."""
    if inp.take() != '"':
        _fail("expected '\"' to open string")
    out = []
    while not inp.empty:
        char = inp.take()
        if char == "\\":
            if inp.empty:
                _fail("trailing backslash in string")
            next_char = inp.take()
            if next_char not in ('"', "\\"):
                _fail("invalid escape in string")
            out.append(next_char)
        elif char == '"':
            return String("".join(out))
        elif char <= "\x1f" or char >= "\x7f":
            _fail("invalid character in string")
        else:
            out.append(char)
    _fail("unterminated string")


def _parse_token(inp: _Input) -> Token:
    """Parse a Token (RFC 9651, Section 4.2.6)."""
    if not (inp.peek() in _ALPHA or inp.peek() == "*"):
        _fail("expected token")
    return Token(inp.take_while(_TOKEN_CHARS))


def _parse_byte_sequence(inp: _Input) -> bytes:
    """Parse a Byte Sequence (RFC 9651, Section 4.2.7)."""
    if inp.take() != ":":
        _fail("expected ':' to open byte sequence")
    content = inp.take_until(":")
    if content is None:
        _fail("unterminated byte sequence")
    inp.take()  # closing ":"
    if any(char not in _B64_CHARS for char in content):
        _fail("invalid base64 character")
    # Synthesize padding; per Section 4.2.7 parsers should not fail on missing
    # "=" padding.
    padded = content + "=" * (-len(content) % 4)
    try:
        return _base64.b64decode(padded, validate=True)
    except (_binascii.Error, ValueError) as exc:
        msg = "invalid base64"
        raise StructuredFieldError(msg) from exc


def _parse_boolean(inp: _Input) -> bool:
    """Parse a Boolean (RFC 9651, Section 4.2.8)."""
    if inp.take() != "?":
        _fail("expected '?' to open boolean")
    char = inp.take()
    if char == "1":
        return True
    if char == "0":
        return False
    _fail("expected '0' or '1'")


def _parse_date(inp: _Input) -> Date:
    """Parse a Date (RFC 9651, Section 4.2.9)."""
    if inp.take() != "@":
        _fail("expected '@' to open date")
    number = _parse_integer_or_decimal(inp)
    if isinstance(number, Decimal):
        _fail("date must be an integer")
    return Date(number)


def _parse_display_string(inp: _Input) -> DisplayString:
    """Parse a Display String (RFC 9651, Section 4.2.10)."""
    if inp.take(2) != '%"':
        _fail("expected '%\"' to open display string")
    byte_array = bytearray()
    while not inp.empty:
        char = inp.take()
        if char <= "\x1f" or char >= "\x7f":
            _fail("invalid character in display string")
        if char == "%":
            octet_hex = inp.take(2)
            if len(octet_hex) != 2:
                _fail("truncated percent-encoding")
            if any(ch not in _LC_HEXDIG for ch in octet_hex):
                _fail("invalid percent-encoding")
            byte_array.append(int(octet_hex, 16))
        elif char == '"':
            try:
                return DisplayString(byte_array.decode("utf-8"))
            except UnicodeDecodeError as exc:
                msg = "display string is not valid UTF-8"
                raise StructuredFieldError(msg) from exc
        else:
            byte_array.append(ord(char))
    _fail("unterminated display string")
