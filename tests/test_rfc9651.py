import decimal

import pytest

from abnf.grammars import rfc9651
from abnf.grammars.rfc9651 import (
    Date,
    Decimal,
    Dictionary,
    DisplayString,
    InnerList,
    Integer,
    Item,
    List,
    Parameters,
    StructuredFieldError,
    Token,
    parse_dictionary,
    parse_item,
    parse_list,
)

# ---------------------------------------------------------------------------
# Layer 1: grammar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule, src",
    [
        ("sf-item", "42"),
        ("sf-item", "-42"),
        ("sf-item", "4.5"),
        ("sf-item", '"a string"'),
        ("sf-item", "sf_token"),
        ("sf-item", "*token"),
        ("sf-item", "token:with/extras"),
        ("sf-item", ":aGVsbG8=:"),
        ("sf-item", "?0"),
        ("sf-item", "?1"),
        ("sf-item", "@1659578233"),
        ("sf-item", '%"caf%c3%a9"'),
        ("sf-item", '2.5;lang="en";q=0.8'),
        ("sf-list", 'sugar, tea, "rum"'),
        ("sf-list", "(1 2 3)"),
        ("sf-list", '("foo" "bar");a=1, baz'),
        ("sf-list", "1, 2, 3"),
        ("sf-dictionary", "en=?1, fr=?0"),
        ("sf-dictionary", "a=1, b=2;x=1, c=(1 2)"),
        ("sf-dictionary", "rating=1.5, feelings=(joy sadness)"),
    ],
)
def test_grammar_accepts(rule: str, src: str):
    assert rfc9651.Rule(rule).parse_all(src)


@pytest.mark.parametrize(
    "rule, src",
    [
        ("sf-item", '"unterminated'),
        ("sf-item", "@1.5"),  # date must be an integer
        ("sf-item", "1234567890123456"),  # 16 integer digits
        ("sf-item", "1.2345"),  # 4 fractional digits
        ("sf-list", "a,"),  # trailing comma
        ("sf-item", "%bad"),  # display string needs %"
    ],
)
def test_grammar_rejects(rule: str, src: str):
    from abnf.parser import ParseError

    with pytest.raises(ParseError):
        rfc9651.Rule(rule).parse_all(src)


# ---------------------------------------------------------------------------
# Layer 2: bare item types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "src, expected",
    [
        ("42", Integer(42)),
        ("-42", Integer(-42)),
        ("0", Integer(0)),
        ("999999999999999", Integer(999999999999999)),
        ("-999999999999999", Integer(-999999999999999)),
    ],
)
def test_parse_integer(src: str, expected: Integer):
    item = parse_item(src)
    assert item.value == expected
    assert isinstance(item.value, Integer)


@pytest.mark.parametrize(
    "src, expected",
    [
        ("4.5", decimal.Decimal("4.5")),
        ("-4.5", decimal.Decimal("-4.5")),
        ("1.230", decimal.Decimal("1.230")),
        ("123456789012.123", decimal.Decimal("123456789012.123")),
    ],
)
def test_parse_decimal(src: str, expected):
    item = parse_item(src)
    assert item.value == expected
    assert isinstance(item.value, Decimal)


def test_parse_string():
    item = parse_item('"hello world"')
    assert item.value == "hello world"
    assert isinstance(item.value, rfc9651.String)


def test_parse_string_escapes():
    assert parse_item(r'"a\"b\\c"').value == 'a"b\\c'


def test_parse_token():
    item = parse_item("foo123:bar/baz")
    assert item.value == "foo123:bar/baz"
    assert isinstance(item.value, Token)


def test_parse_byte_sequence():
    item = parse_item(":aGVsbG8=:")
    assert item.value == b"hello"
    assert isinstance(item.value, bytes)


def test_parse_byte_sequence_missing_padding():
    # per Section 4.2.7 padding may be synthesized
    assert parse_item(":aGVsbG8:").value == b"hello"


def test_parse_empty_byte_sequence():
    assert parse_item("::").value == b""


@pytest.mark.parametrize("src, expected", [("?1", True), ("?0", False)])
def test_parse_boolean(src: str, expected: bool):
    assert parse_item(src).value is expected


def test_parse_date():
    item = parse_item("@1659578233")
    assert item.value == 1659578233
    assert isinstance(item.value, Date)


def test_parse_negative_date():
    assert parse_item("@-1000").value == Date(-1000)


def test_parse_display_string():
    item = parse_item('%"caf%c3%a9"')
    assert item.value == "café"
    assert isinstance(item.value, DisplayString)


# ---------------------------------------------------------------------------
# Layer 2: parameters, items, inner lists
# ---------------------------------------------------------------------------


def test_parse_item_with_parameters():
    item = parse_item('2.5;lang="en";q=0.8')
    assert item.value == decimal.Decimal("2.5")
    assert item.params == Parameters({"lang": "en", "q": decimal.Decimal("0.8")})


def test_parse_boolean_parameter_defaults_true():
    item = parse_item("sugar;a;b=?0")
    assert item.params == Parameters({"a": True, "b": False})


def test_parse_list_of_items():
    result = parse_list('sugar, tea, "rum"')
    assert result == List(
        [Item(Token("sugar")), Item(Token("tea")), Item(rfc9651.String("rum"))]
    )


def test_parse_inner_list():
    result = parse_list("(1 2 3)")
    assert len(result) == 1
    inner = result[0]
    assert isinstance(inner, InnerList)
    assert [i.value for i in inner.items] == [1, 2, 3]


def test_parse_inner_list_with_parameters():
    result = parse_list('("foo" "bar");a=1, baz')
    inner = result[0]
    assert isinstance(inner, InnerList)
    assert [i.value for i in inner.items] == ["foo", "bar"]
    assert inner.params == Parameters({"a": Integer(1)})
    assert result[1] == Item(Token("baz"))


def test_parse_empty_inner_list():
    result = parse_list("()")
    assert result[0] == InnerList([])


# ---------------------------------------------------------------------------
# Layer 2: dictionaries
# ---------------------------------------------------------------------------


def test_parse_dictionary():
    result = parse_dictionary("en=?1, fr=?0")
    assert result == Dictionary({"en": Item(True), "fr": Item(False)})


def test_parse_dictionary_bare_key_is_true():
    result = parse_dictionary("a, b=2")
    assert result["a"] == Item(True)
    assert result["b"] == Item(Integer(2))


def test_parse_dictionary_inner_list_member():
    result = parse_dictionary("a=(1 2), b=3")
    assert isinstance(result["a"], InnerList)
    assert result["b"] == Item(Integer(3))


# ---------------------------------------------------------------------------
# Layer 2: algorithmic rules that ABNF cannot express
# ---------------------------------------------------------------------------


def test_duplicate_dictionary_keys_last_wins():
    result = parse_dictionary("a=1, b=2, a=3")
    assert result["a"] == Item(Integer(3))
    # order is preserved from first occurrence
    assert list(result.keys()) == ["a", "b"]


def test_duplicate_parameter_keys_last_wins():
    item = parse_item("x;a=1;a=2")
    assert item.params == Parameters({"a": Integer(2)})


def test_invalid_base64_fails():
    with pytest.raises(StructuredFieldError):
        parse_item(":!!!:")


def test_invalid_utf8_display_string_fails():
    with pytest.raises(StructuredFieldError):
        parse_item('%"%ff"')


def test_uppercase_hex_display_string_fails():
    with pytest.raises(StructuredFieldError):
        parse_item('%"%C3%A9"')


def test_leading_and_trailing_spaces_stripped():
    assert parse_item("   42   ").value == Integer(42)


def test_leading_tab_not_stripped():
    with pytest.raises(StructuredFieldError):
        parse_item("\t42")


def test_empty_list_and_dictionary():
    assert parse_list("") == List()
    assert parse_dictionary("") == Dictionary()
    assert parse_list("   ") == List()


def test_empty_item_fails():
    with pytest.raises(StructuredFieldError):
        parse_item("")


def test_trailing_comma_fails():
    with pytest.raises(StructuredFieldError):
        parse_list("a, b,")
    with pytest.raises(StructuredFieldError):
        parse_dictionary("a=1,")


def test_non_ascii_fails():
    with pytest.raises(StructuredFieldError):
        parse_item("café")


@pytest.mark.parametrize(
    "src",
    [
        "1234567890123456",  # 16 integer digits
        "12345678901234.5",  # 13 digits before the decimal point
        "1.2345",  # 4 fractional digits
        "1.",  # no fractional digits
        "-",  # sign with no digits
    ],
)
def test_invalid_numbers_fail(src: str):
    with pytest.raises(StructuredFieldError):
        parse_item(src)


def test_date_with_decimal_fails():
    with pytest.raises(StructuredFieldError):
        parse_item("@1.5")


def test_unterminated_string_fails():
    with pytest.raises(StructuredFieldError):
        parse_item('"foo')


def test_unterminated_inner_list_fails():
    with pytest.raises(StructuredFieldError):
        parse_list("(1 2")


@pytest.mark.parametrize(
    "fn, src",
    [
        (parse_item, "42 43"),  # trailing characters after item
        (parse_item, "~"),  # unrecognized bare item
        (parse_item, "123456789012.3456"),  # decimal too long
        (parse_item, '"a\x01b"'),  # control character in string
        (parse_item, r'"a\xb"'),  # invalid escape in string
        (parse_item, '"foo\\'),  # trailing backslash in string
        (parse_item, ":abc"),  # byte sequence with no closing colon
        (parse_item, "-x"),  # sign followed by a non-digit
        (parse_item, ":A:"),  # base64 that fails to decode
        (parse_item, "?2"),  # boolean that is neither 0 nor 1
        (parse_item, '%"a%"'),  # truncated percent-encoding
        (parse_item, '%bad"'),  # display string missing opening DQUOTE
        (parse_item, '%"ctrl\x01"'),  # control character in display string
        (parse_item, '%"abc'),  # unterminated display string
        (parse_list, "a b"),  # missing comma between list members
        (parse_list, "("),  # inner list with no closing paren
        (parse_list, "(1,2)"),  # bad separator inside inner list
        (parse_dictionary, "a=1 b=2"),  # missing comma between dict members
        (parse_dictionary, "1=2"),  # dictionary key must start lcalpha/*
        (parse_item, "x;1=2"),  # parameter key must start lcalpha/*
    ],
)
def test_error_paths(fn, src: str):
    with pytest.raises(StructuredFieldError):
        fn(src)


# ---------------------------------------------------------------------------
# Layer 2: model helpers
# ---------------------------------------------------------------------------


def test_model_containers_are_unhashable():
    with pytest.raises(TypeError):
        hash(Item(Integer(1)))
    with pytest.raises(TypeError):
        hash(InnerList([Item(Integer(1))]))


def test_item_repr_and_equality():
    assert Item(Integer(1)) == Item(Integer(1))
    assert Item(Integer(1)) != Item(Integer(2))
    assert Item(Integer(1), Parameters({"a": True})) != Item(Integer(1))
    assert repr(Item(Integer(1))) == "Item(1, {})"


def test_inner_list_repr_and_equality():
    assert InnerList([Item(Integer(1))]) == InnerList([Item(Integer(1))])
    assert InnerList([Item(Integer(1))]) != InnerList([Item(Integer(2))])
    assert repr(InnerList([], Parameters({"a": True}))) == "InnerList([], {'a': True})"
