# What abnf parses: code points, not bytes

`abnf` parses **sequences of Unicode code points**. A Python `str` is exactly
that, which is why `parse` and `parse_all` take a `str` and nothing else.

That one sentence answers most of the questions people arrive with, including
"can it parse bytes?" — see [Parsing wire data](#parsing-wire-data) below, where
the answer is yes, with a one-line decode.

## Terminal values are code-point values

In ABNF a terminal is written as a numeric value: `%x41` is `A`, `%d97` is `a`,
`%x61-7A` is the range `a`–`z`. `abnf` reads those as **code-point** values, so
they mean what the RFC that wrote them meant:

```text
ALPHA   = %x41-5A / %x61-7A          ; ASCII letters
ucschar = %xA0-D7FF / %xF900-FDCF / %x10000-1FFFD / ...   ; RFC 3987, IRIs
```

`%x10000-1FFFD` is a range of astral-plane characters, and matching it against a
`str` works because a `str` holds code points. There is no encoding step and no
encoding assumption anywhere in the parse.

## Parsing wire data

Protocol data arrives as bytes, and ABNF grammars for protocols are written in
octets: `OCTET = %x00-FF`, `obs-text = %x80-FF`. Decode with **latin-1** and one
code point is exactly one octet:

```python
from abnf.grammars import rfc7230

raw = b"GET /index.html HTTP/1.1\r\n"          # bytes off the wire
rfc7230.Rule("request-line").parse_all(raw.decode("latin-1"))
```

latin-1 maps the 256 byte values onto the 256 code points `U+0000`–`U+00FF`, one
to one, in both directions. It is total — every byte string decodes, including
arbitrary binary — and `.encode("latin-1")` returns the original bytes exactly.
It costs nothing: CPython stores such a string at one byte per code point, so
the decode is a copy with no change in memory footprint.

```{important}
Which encoding you decode with is a semantic choice, and `abnf` cannot make it
for you. Consider two octets of UTF-8:

    raw = b"\xc3\xa9"                        # 'é' encoded as UTF-8

    1*OCTET against raw.decode("latin-1")    -> 2 octets
    1*OCTET against raw.decode("utf-8")      -> 1 octet

Both are right. The first reads the data as a byte protocol, where `OCTET` means
octet and there are two of them. The second reads it as text, where there is one
character. If you are parsing an HTTP header or an email message, you want
latin-1: those grammars count octets.
```

## Surrogates

Code points `U+D800`–`U+DFFF` are surrogates. They are legal in a Python `str`
but have no character meaning, and they arrive in real data — `surrogateescape`
is how Python represents undecodable bytes in filenames, `sys.argv`, and
environment variables, and an unpaired `\uD800` survives `json.loads`.

A grammar can name them (`%xD800-DBFF`) and match them, but whether they appear
at all depends on how *you* decoded: a strict `utf-8` or `utf-16` decode
rejects them, while `surrogatepass` and `surrogateescape` preserve them. That
is a property of the decode, not of the parser.

Both backends handle them, and identically. The Rust engine used to work in
`char` and `&str` — Unicode *scalar values* and well-formed UTF-8, neither of
which can hold a surrogate — so a grammar naming one failed to load and input
containing one failed to cross the FFI. Since 2.7.0 it indexes by code point
like the pure-Python backend, and both accept the whole domain
([issue #173](https://github.com/declaresub/abnf/issues/173)).

## Case-insensitivity is ASCII-only

A quoted string in a grammar is case-insensitive by default — `"chunked"`
matches `Chunked` — and RFC 5234 §2.3 fixes the character set for those
literals as US-ASCII. `abnf` folds case over US-ASCII and nothing else, so
matching stays inside the character set the grammar is written in:

```python
Rule("transfer-coding").parse_all("CHUNKED")        # matches
Rule("transfer-coding").parse_all("chun\u212aed")   # KELVIN SIGN: no match
```

Full Unicode case folding — Python's `str.casefold()`, which is what `abnf`
used before 2.7.0 — would match both, because `'\u212a'.casefold() == 'k'`.
That over-accepts against an ASCII grammar, and it disagrees with peers that
fold only ASCII, which is where protocol parsers get their differentials.

Folding only ASCII is also length-preserving, so a literal always consumes
exactly as many code points as it has. Under full folding it did not:
`'ß'.casefold()` is `'ss'`, so `"ss"` matched a lone `'ß'` but not the `'ß'` in
`'ßx'`, because the comparison folds a fixed-width window of the source.

A literal containing non-ASCII characters still matches itself exactly; folding
leaves those code points alone rather than rejecting them.

## Why there is no bytes API

A `bytes` entry point would buy no capability — latin-1 already gives exact
octet semantics — while costing an `encoding` parameter, a second node-value
type, and a permanent second path through the parser. The decode is one method
call and stays where the knowledge lives: with the caller who knows what their
data is. See [issue #25](https://github.com/declaresub/abnf/issues/25) for the
full reasoning.
