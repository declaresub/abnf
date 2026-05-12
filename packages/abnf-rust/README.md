# abnf-rust

Rust-backed parser engine for the [`abnf`](https://pypi.org/project/abnf/)
package.

This is a companion distribution: install it via

```
pip install abnf[rust]
```

The package supplies the importable Python module `abnf_rust`, a compiled
extension built with PyO3 that accelerates the combinator engine in
`abnf.parser`. When `abnf_rust` is importable, `abnf.parser` automatically
routes its combinator primitives through this module; the pure-Python
implementation in `abnf._parser_python` remains available as a fallback and
as the reference for behavior parity.

To force the pure-Python backend even when `abnf-rust` is installed, set
the environment variable `ABNF_NO_RUST=1`.

## Layout

* `rust/core/` — pure-Rust parser engine (no Python dependency).
* `rust/pyo3/` — PyO3 bindings, compiled to `abnf_rust._ext`.
* `src/abnf_rust/` — Python wrapper package that re-exports the compiled
  symbols.

## Building

```
maturin develop --manifest-path packages/abnf-rust/Cargo.toml
```

## License

MIT.
