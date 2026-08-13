# Configuration

The knobs that change parsing behavior.

## `Rule.first_match_alternation`

A class attribute on a `Rule` subclass. Selects how alternation resolves:

- `False` (default) — **longest match** wins; ties are broken by declaration
  order.
- `True` — the **first** matching alternative is returned immediately.

```python
class MyGrammar(Rule):
    first_match_alternation = True
```

See {doc}`../explanation/alternation-semantics` for why this is configurable.

## `ParseCache.max_cache_size` (deprecated)

Formerly bounded the parse cache. There is nothing left to bound: memoisation is
scoped to a single parse and discarded when it returns, so no parse state
survives a call. Assigning it raises a `DeprecationWarning`, as does
`ParseCache.clear_caches()`.

Earlier versions of this page documented the attribute as `Rule.max_cache_size`.
No such attribute ever existed -- it lives on `ParseCache` -- so code following
that advice has always been a no-op.

To reuse a parse result across calls, memoize at the call site:

```python
import functools

parse_host = functools.lru_cache(maxsize=1024)(rfc9110.Rule("Host").parse_all)
```

See {doc}`../explanation/backtracking-and-caching`.

## `ABNF_NO_RUST` (environment variable)

When set (to any value), forces the pure-Python backend even if the optional
`abnf_rust` extension is installed. Useful for debugging, benchmarking, or A/B
comparison. The dispatch is decided once, at import time.

```console
ABNF_NO_RUST=1 python your_script.py
```

See {doc}`../explanation/backends` and {doc}`../how-to/use-the-rust-backend`.

## Line endings

ABNF uses CRLF (`\r\n`) as the delimiter between rules in a rulelist. When loading
a grammar from text (`Rule.create`, `Rule.load_grammar`, `Rule.from_file`), input
is normalized to CRLF by default. Beware that some text editors silently rewrite
line endings.
