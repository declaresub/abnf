# The two backends

abnf has two interchangeable parser implementations behind the same public API:

- **Pure Python** (`abnf._parser_python`) — the default. Always available, depends
  only on the standard library, and serves as the executable reference for the
  combinator semantics.
- **Rust** (`abnf_rust._ext`, installed via `pip install abnf[rust]`) — a PyO3
  extension that reimplements the combinator engine and the ABNF meta-grammar in
  Rust.

When the Rust extension is importable, `abnf.parser` rebinds its combinator
primitives — `Alternation`, `Concatenation`, `Repetition`, `Option`, `Literal`,
`Prose`, `Repeat`, `Match`, `Node`, `LiteralNode` — to the Rust pyclasses. `Rule`,
`NodeVisitor`, `ParseError`, and `GrammarError` remain Python in either case, so
subclassing, the per-class rule registry, and reflective visitor dispatch continue
to work unchanged.

The public API is identical either way, including every bundled grammar module and
every example in this documentation.

## Dispatch

The choice is made **once, at import time** in `abnf.parser`, based on whether the
companion `abnf_rust` extension is importable. Set the environment variable
`ABNF_NO_RUST=1` to force the pure-Python backend even when the extension is
installed. Because dispatch happens at import, the variable must be set before
`abnf` is first imported.

The module attribute `abnf.parser._BACKEND` is `"python"` or `"rust"` and reflects
the active backend.

For guidance on which to install and how to build the extension for development,
see {doc}`../how-to/use-the-rust-backend`. For where the Rust backend pays off, see
{doc}`rust-backend-performance`.
