# Use the Rust backend

The optional Rust backend parses substantially faster (typically 6–10× on
backtracking-heavy grammars) while keeping the public API identical. See
{doc}`../explanation/rust-backend-performance` for benchmark numbers and where the
speed-up is largest.

## Install it

Install the `rust` extra with whichever installer you use:

```console
pip install 'abnf[rust]'
uv pip install 'abnf[rust]'
uv add 'abnf[rust]'
poetry add 'abnf[rust]'
```

(Most shells need the quotes around `abnf[rust]` because `[...]` is a glob
pattern.) That's all — `abnf.parser` picks up the `abnf_rust` extension
automatically at import. Nothing in your code changes.

## Force the pure-Python backend

Set `ABNF_NO_RUST=1` before `abnf` is first imported to use the pure-Python
implementation even when the extension is installed:

```console
ABNF_NO_RUST=1 python your_script.py
```

Useful for debugging parser internals, A/B comparison, or reproducing behavior on a
machine without the extension. You can confirm which backend is active:

```python
import abnf.parser
abnf.parser._BACKEND   # 'python' or 'rust'
```

## When to skip it

The pure-Python implementation is a complete, supported parser and is the right
choice when:

- the deployment target rejects compiled extensions (e.g. some zip-deployed AWS
  Lambda layers or constrained container images);
- you want to step through parser internals — the pure-Python code is shorter,
  generator-based, and trivially traceable;
- `ABNF_NO_RUST=1` is convenient for a comparison.

## Build it for development

To build and install the extension against your dev virtualenv (driving
[maturin](https://www.maturin.rs/), the declared PEP 517 backend):

```console
pip install -e ./packages/abnf-rust
uv pip install -e ./packages/abnf-rust
```

Subsequent runs rebuild only what changed. Force the pure-Python backend in the test
suite with `ABNF_NO_RUST=1 pytest`, and run the Rust crate's own tests with:

```console
cargo test --manifest-path packages/abnf-rust/Cargo.toml
```
