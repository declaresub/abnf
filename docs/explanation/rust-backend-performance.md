# Rust backend performance

When the `abnf-rust` companion is installed (`pip install abnf[rust]`),
`abnf.parser` transparently dispatches its combinator primitives to a Rust
extension built with PyO3. The public API is unchanged; set `ABNF_NO_RUST=1` to
force the pure-Python backend at runtime. This page explains where the Rust backend
helps and where the gap narrows — see {doc}`backends` for how dispatch works and
{doc}`../how-to/use-the-rust-backend` for installing and building it.

Representative benchmarks (median of three runs of `pytest tests/benchmarks/`,
Apple Silicon):

| Grammar / input | Pure Python | Rust | Speed-up |
|---|---|---|---|
| RFC 3986 URI `https://user:pass@example.com:8080/a/b/c?q=1&r=2#frag` | 190 µs | 28.4 µs | **6.7×** |
| RFC 5322 mailbox `Charles Yeomans <charles@example.com>` | 422 µs | 44.9 µs | **9.4×** |
| RFC 7230 request-line `GET /index.html HTTP/1.1\r\n` | 73 µs | 10.4 µs | **7.0×** |
| RFC 9051 astring `HelloWorld42` | 5.9 µs | 4.0 µs | **1.5×** |
| Fuzz suite (512 cases, inputs up to 138 KB) | 9.1 s | 1.42 s | **6.4×** |

## Where the Rust backend helps most

The Rust backend's biggest advantage is **how cheaply it rejects parses that don't
match**. ABNF parsing is built around alternation and optional groups: on every
backtracking step the algorithm tries an alternative, watches it fail, and moves
on. The Python combinator's failure path raises a `ParseError`, propagates it
through generator exception machinery, and unwinds Python frames — all comparatively
expensive. The Rust equivalent is a single `Err(...)` return value with no string
formatting. Grammars that exercise this path heavily — RFC 5322's deeply-nested
`FWS` and `CFWS` whitespace handling is the classic example — see the biggest wins.

The advantage compounds with the number of candidate parses considered at each
step. RFC 3986's URI grammar enumerates dozens of partial-parse candidates (optional
`[ "?" query ]`, optional `[ "#" fragment ]`, multiple `hier-part` alternatives);
each losing candidate costs only a few hundred nanoseconds in Rust.

## Where the gap narrows

The Rust backend is *less* dominant on tight grammars whose work is mostly
*successful* tree-building rather than backtracking. The clearest example is the
RFC 9051 `astring` row above. Parsing `HelloWorld42` against

```abnf
astring = 1*ASTRING-CHAR / string
```

is essentially twelve successful `ASTRING-CHAR` matches plus a single near-instant
failure on the `string` arm. Each successful match builds a small parse-tree node,
and CPython optimizes that build path extremely well: a small list allocation goes
through CPython's `list` freelist and costs only a handful of nanoseconds. The Rust
equivalent allocates an `Arc<Vec<NodeKind>>` per node and crosses the PyO3 boundary
— both fast, but still a few times more expensive than CPython's open-coded path.
The Rust backend still wins on `astring`, but only modestly.

Roughly:

| Grammar shape | Typical Rust speed-up |
|---|---|
| Heavy alternation / optional / deep backtracking | 6–10× |
| Mixed: moderate alternation with tree-building | 3–6× |
| Pure linear success with few alternatives | 1.5–2× |

In other words: the more an ABNF grammar exercises backtracking — which most real
RFC grammars do — the bigger the win. We have not observed a grammar on which the
Rust backend is slower than the pure-Python implementation.

## Even without the extra

Much of the optimization work motivated by the Rust port (lazy `Rule.lparse`,
sorted `Alternation`, `Match` hash caching, dedup-by-end-position in `Repetition`)
also landed in the pure-Python implementation, so even without the `[rust]` extra
abnf parses meaningfully faster than its historical baseline.
