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

Each entry is about 1.6 KiB, but the entry is not the whole cost: it points at a
compiled parser tree, and the Python `Rule` and its own tree stay alive too.
Measured end to end over 2,000 dynamically created three-rule grammars (6,040
rules), resident memory grows by 13.3 MiB on the pure-Python backend and 35.7
MiB on the Rust backend — 2.2 and 6.1 KiB per rule respectively.

For the ordinary case — importing grammar modules once at startup — this is a
fixed cost and nothing to think about. It only accumulates if you build grammars
at runtime: calling `Rule.create` on freshly-defined `Rule` subclasses in a loop,
say, or per request. Note the pure-Python `Rule._obj_map` grows the same way and
is not reclaimed either, so this is not specific to the Rust backend.

```{note}
There is no way to reclaim this memory, and that is deliberate. A private
`clear_bridge()` used to empty the registry; it was removed in 2.8.0 because it
could not do the job and broke correctness in the attempt.

Clearing frees very little: a rule's compiled tree embeds the handles of the
rules it references, so those trees stay alive through the grammar that uses
them, and the Python side retains its share regardless. What it does do is
desynchronise the two sides. The 40 baseline entries are the core rules, so any
grammar defined *after* a clear gets a fresh, empty handle for `ALPHA`, `DIGIT`
and friends, and silently fails to parse input it should accept; redefining a
rule after a clear silently loses the change, because live trees still hold the
old handle.

If you build grammars at runtime and the growth matters, the lever is on the
Python side. Growth tracks *distinct rules ever created*, not parses: parsing
2,000 times through an already-built grammar costs nothing measurable. So cache
the `Rule` subclass for a given grammar and reuse it, rather than defining a
fresh subclass each time you need it. `Rule._obj_map` is keyed by
`(class, name)`, so redefining a rule on a class you already have replaces the
entry instead of adding one — though it also raises `GrammarWarning` each time,
which is a good sign you meant to reuse the built grammar instead.
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
