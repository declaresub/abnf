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

## Memory in a long-running process

The engine keeps a registry mapping each Python `Rule` to its compiled
counterpart. Entries are added when a rule is defined and are never removed, so
the registry grows with the number of rules a process has ever created:

| | entries |
|---|---|
| `import abnf` (the RFC 5234 core rules) | 40 |
| plus all 32 bundled grammar modules | 1,176 |
| plus 2,000 dynamically created grammars | 3,176 |

At roughly 1.6 KiB per entry, the 2,000 dynamic grammars above cost about 3 MiB.

For the ordinary case — importing grammar modules once at startup — this is a
fixed cost and nothing to think about. It only accumulates if you build grammars
at runtime: calling `Rule.create` on freshly-defined `Rule` subclasses in a loop,
say, or per request. Note the pure-Python `Rule._obj_map` grows the same way and
is not reclaimed either, so this is not specific to the Rust backend.

```{warning}
`abnf_rust._ext` exposes `clear_bridge()`, which empties the registry. It is a
private diagnostic, not a supported knob, and calling it is **not safe**: the
40 baseline entries are the core rules, so any grammar defined *after* a clear
gets a fresh, empty handle for `ALPHA`, `DIGIT` and friends and silently fails
to parse input it should accept.

Grammars that were already fully built keep working — they hold their compiled
handles directly — but redefining one of their rules after a clear also silently
loses the change. There is currently no supported way to reclaim this memory --
see [issue #187](https://github.com/declaresub/abnf/issues/187).
```

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
