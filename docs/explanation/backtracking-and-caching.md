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
`(source, start)` is computed once and reused when backtracking revisits it.
Failures are cached too (as a `_CachedParseError`), so a sub-parse that cannot
match at a position is not retried there.

The cache is an LRU, `ParseCache`. By default it is unbounded, which is fine for
one-shot parses but can grow without limit in a long-lived process that parses many
distinct inputs. Set `Rule.max_cache_size` to a non-negative integer to bound it
(see {doc}`../reference/configuration`).

```{note}
The pure-Python parser is recursive-descent, so extremely deeply-nested input can
exceed the Python recursion limit. Rather than crashing with `RecursionError`, the
pure-Python backend reports this as a `ParseError`. If you must parse very deeply
nested input, `Rule.parse_all` documents a worker-thread recipe with a larger
stack.
```

For how much the backtracking cost differs between the two backends — the Rust
backend's cheap failure path is its single biggest advantage — see
{doc}`rust-backend-performance`.
