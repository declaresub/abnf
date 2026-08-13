# Backtracking and caching

abnf implements backtracking as of version 2.0.0. This was a change in behavior
significant enough to warrant the major version bump.

Backtracking is what lets alternation and optional groups explore alternatives: at
each step the algorithm tries a candidate, and if a later part of the parse fails,
it retreats and tries the next candidate. It is also the source of a well-known
hazard — naive backtracking parsers have **exponential** worst-case running time,
because the same sub-parse can be attempted over and over along different paths.

abnf keeps this in check two ways.

## Laziness

Each combinator's `lparse` is a **generator** that yields matches on demand.
Callers that only need the first result — for example `Rule.parse`, which wants the
single longest match — pull one value and stop, so the losing candidates are never
materialized. Matches are yielded longest-first and de-duplicated by end position,
so an ambiguous grammar does not pay to build every candidate parse tree.

## Caching

`Repetition` objects memoize their results: a repeated sub-parse at a given
position is computed once and reused when backtracking revisits it. Failures are
memoized too, so a sub-parse that cannot match at a position is not retried
there.

**The memo lives for exactly one parse.** It is created when `parse` or
`parse_all` is called and discarded when that call returns. Both backends work
this way — the pure-Python one binds a context variable, the Rust engine stamps
entries with a per-parse epoch.

Two consequences worth knowing:

- **Nothing is retained between parses.** A long-lived process parsing many
  distinct inputs holds no parse state at all. There is no cache to bound and
  no cache to clear.
- **Re-parsing the same source repeats the work.** The memo cannot answer the
  second call, because it no longer exists.

If you parse a byte-identical source repeatedly — validating the same `Host`
header on every request, say — memoize at the call site:

```python
import functools

parse_host = functools.lru_cache(maxsize=1024)(rfc9110.Rule("Host").parse_all)
```

That is not a workaround; it is strictly better than an internal cache could be.
It skips the parse outright instead of replaying sub-results, which measures
roughly a thousand times faster, and its size and lifetime belong to the code
that knows the working set.

```{note}
`ParseCache`, `ParseCache.clear_caches()` and `ParseCache.max_cache_size` are
deprecated: the parser no longer uses them, so they have nothing left to bound
or clear. Assigning `max_cache_size` or calling `clear_caches()` raises a
`DeprecationWarning`. Earlier releases also documented `Rule.max_cache_size`,
which never existed — the attribute lived on `ParseCache` — so any code setting
it has always been a no-op.
```

```{note}
Both parsers are recursive-descent, so extremely deeply-nested input eventually
runs out of room. Rather than crashing, both report it as a `ParseError`: the
pure-Python backend when it exceeds the Python recursion limit, the Rust backend
when nested rules exhaust its native-stack budget (about 180 levels — lower than
the Python backend's, but identical on every platform and every thread).

To parse input nested more deeply than that, use the pure-Python backend, whose
limit you can raise: force it with `ABNF_NO_RUST=1` and follow the worker-thread
recipe in `Rule.parse_all`.
```

For how much the backtracking cost differs between the two backends — the Rust
backend's cheap failure path is its single biggest advantage — see
{doc}`rust-backend-performance`.
