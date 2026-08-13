# Changelog

## Unreleased

* `Rule.exclude_rule` now applies to nested rule references under the Rust
  backend.  It never had: the exclusion lives in the pure-Python `Rule.lparse`,
  and the Rust engine resolves rule references internally, entering that method
  only for the rule the caller parses directly.  A grammar written as
  "identifier, but not a keyword" therefore accepted keywords whenever the
  keyword rule appeared nested inside another rule -- a validator answering
  "valid" for input it was written to reject.  `Rule.exclude_rule` now forwards
  through the bridge the way `Rule.definition` already did, and the engine drops
  matches whose span parses completely as the excluded rule, matching the
  pure-Python semantics exactly (a partial match still does not disqualify).
  https://github.com/declaresub/abnf/issues/179

* Memoisation is now scoped to a single parse on both backends, which fixes two
  silent wrong-result bugs and a memory leak at once.

  The `Repetition` cache used to live on the parser object and survive across
  calls.  In the pure-Python backend it was keyed `(source, start)` and never
  invalidated, so mutating a grammar after parsing with it -- `=/`, rule
  redefinition, `Rule.exclude_rule`, or toggling `first_match_alternation` --
  left stale results that silently overrode the new grammar.  In the Rust
  backend it was keyed on position alone, with the source identified by its
  address plus a fingerprint sampled from the first and last 64 bytes; two
  sources of equal length differing only in between -- with the second at the
  freed address of the first, which CPython's allocator does routinely -- were
  taken for the same source, and the second parse returned the first one's
  text.

  Both are gone by construction.  The memo is created when `parse` is called
  and discarded when it returns, so a grammar cannot change underneath it and
  nothing is retained: parsing 2,000 distinct URIs previously grew the heap by
  174 MiB with a 0% hit rate, and now grows it by nothing.  Cold parses got
  faster on both backends -- 1-21% (Python) and 7-11% (Rust) -- because the
  bookkeeping this replaces was not free.

  **Re-parsing a byte-identical source now repeats the work**, since the memo
  no longer outlives the call.  If you rely on that, memoize at the call site
  with `functools.lru_cache`; it skips the parse entirely rather than replaying
  sub-results, so it is far faster than the internal cache ever was, and its
  size and lifetime belong to the code that knows the working set.

* `ParseCache`, `ParseCache.clear_caches()` and `ParseCache.max_cache_size` are
  deprecated.  The parser no longer holds a `ParseCache`, so there is nothing
  to bound or clear; assigning the attribute or calling `clear_caches()` raises
  a `DeprecationWarning`.  The class remains importable and still works as an
  ordinary mapping.  Note that the documented spelling `Rule.max_cache_size`
  never existed -- the attribute is on `ParseCache` -- so code following the old
  documentation has always been a no-op.

* The parse benchmarks now measure a cold parse per iteration, because there is
  no longer a cross-call cache for later iterations to hit.  Numbers published
  before this change measured cache hits and are not comparable.

### Known issues

* `Rule.exclude_rule` is silently ignored for nested rule references under the
  Rust backend: the exclusion is implemented in the pure-Python `Rule.lparse`,
  which the Rust path enters only for the top-level rule.  A grammar written to
  reject a keyword will accept it.  `ABNF_NO_RUST=1` is a correct workaround.
  https://github.com/declaresub/abnf/issues/179

## 2.7.0

* The Rust backend no longer crashes the interpreter on deeply nested input.
  Its recursion guard bounded the number of nested rule levels (1000, to mirror
  CPython's recursion limit), but the resource that runs out is stack *bytes*:
  a level costs ~3 KiB, so reaching 1000 needs ~3 MiB of native stack.  Where
  the stack was smaller the process died of a stack overflow -- no `ParseError`,
  no `RecursionError`, nothing catchable -- before the level counter came close
  to firing.  That was every Windows user of `abnf[rust]`, and anyone on any
  platform parsing on a thread created with a modest `threading.stack_size`.

  The guard now budgets native stack as well as counting levels, so it fires on
  the resource that actually runs out and behaves identically everywhere.  The
  ceiling is lower as a result: roughly 180 levels of rule nesting rather than
  1000 on platforms whose stack could absorb it.  ABNF grammars nest in the
  single digits in practice; input approaching this bound is pathological, and
  is now reported as a `ParseError` on both backends.  To parse deeper input,
  use the pure-Python backend, whose limit can be raised -- see the
  worker-thread recipe in `Rule.parse_all`.
  https://github.com/declaresub/abnf/issues/170

* `Rule.parse` now validates `start` and raises `ValueError` if it falls outside
  `0 <= start <= len(source)`.  It was previously unchecked, and a negative
  value is a valid Python slice measured from the end of the source, so the
  parse quietly succeeded at a position the caller never asked for and returned
  negative node offsets -- `parse("abcdef", -4)` matched `"cd"`.  The Rust
  backend raised `OverflowError` on the same call, so the two backends
  disagreed on a case where neither answer was right.  `start` is also
  normalised with `operator.index`, so `True` becomes `1` rather than reaching
  `ParseError.start` verbatim, and a non-integer raises `TypeError` with the
  same message on both backends.

* A repetition whose maximum is below its minimum now raises `GrammarError`
  when the grammar is loaded, on both backends.  `3*2"a"` is an impossible
  range, but it silently behaved as `3*"a"` -- rejecting `"aa"` while accepting
  `"aaa"`, `"aaaa"` and so on -- so a typo for `2*3` became unbounded
  repetition with no diagnostic.

* The Rust backend now explains itself when it meets a surrogate code point,
  which it cannot represent because Rust strings are well-formed UTF-8.  A
  grammar containing one (`%xD800-DBFF`) raised `TypeError: value argument must
  be a string or a 2-tuple of strings` -- about a value that *was* a string --
  and input containing one (from `surrogateescape`, or an unpaired `\uD800` out
  of `json.loads`) raised a bare `UnicodeEncodeError` that never mentioned
  `abnf`.  Both now name the surrogate as the cause and point at
  `ABNF_NO_RUST=1`, which selects the pure-Python backend.  The underlying
  limitation is unchanged.
  https://github.com/declaresub/abnf/issues/173

* Document what `abnf` parses: code points, not bytes.  A terminal value in a
  grammar is a code-point value, a Python `str` is a sequence of code points,
  and wire data is parsed by decoding it with latin-1, which maps the 256 byte
  values onto `U+0000`-`U+00FF` one to one so that a code point is exactly an
  octet.  New "What abnf parses" page, a note on `Rule.parse_all`, and a README
  section.  This is why there is no bytes API: latin-1 already gives exact octet
  semantics for one method call.
  https://github.com/declaresub/abnf/issues/174

* CI runs the Rust backend on Windows and macOS, not just Linux.  The compiled
  extension was previously built and tested only on Linux even though wheels
  ship for five targets, which is why the crash above went unnoticed.
  https://github.com/declaresub/abnf/issues/167

### Known issues

* The `Repetition` parse cache is still not invalidated when a grammar is
  mutated after it has been used to parse — via `=/` (incremental definition),
  rule redefinition, `Rule.exclude_rule`, or toggling
  `Rule.first_match_alternation`.  Re-parsing a previously-seen input can then
  return a stale result.  2.6.0 said a fix was planned for the next release;
  it did not make this one.  The bundled grammars remain unaffected — they are
  finalized at import, before any parse — so only code that mutates a grammar
  after parsing with it is exposed.

* The Rust backend cannot represent surrogate code points: a grammar
  containing one raises `GrammarError` and input containing one raises
  `ValueError`, where the pure-Python backend handles both.  Set
  `ABNF_NO_RUST=1` to use the pure-Python backend.
  https://github.com/declaresub/abnf/issues/173

## 2.6.0

* Add grammars for RFC 6797 (HTTP Strict Transport Security), RFC 7240
  (Prefer header), RFC 7838 (HTTP Alternative Services), RFC 8288 (Web
  Linking / Link header), and RFC 9651 (Structured Field Values for HTTP,
  which obsoletes RFC 8941).

* The pure-Python parser now raises `ParseError` instead of an uncaught
  `RecursionError` when input is nested more deeply than the Python
  recursion limit allows, restoring the documented exception contract (the
  Rust backend was already unaffected).  `Rule.parse_all`'s docstring
  documents the depth limit and a worker-thread recipe for parsing very
  deeply nested input.
  https://github.com/declaresub/abnf/issues/144

* Fix the CORS `Origin` header grammar to accept the ASCII string `"null"`,
  and warn on rule redefinition.  The root cause was a case-insensitive
  rule-name collision between `Origin` and `origin`; the grammar now uses
  the current Fetch standard's self-contained serialized-origin
  productions.
  https://github.com/declaresub/abnf/issues/135

* Documentation is now a full site organized by the Diátaxis framework,
  hosted at <https://abnf.readthedocs.io/>.  The README is now a landing
  page.

* Testing: every RFC grammar module now has generative / differential
  fuzz coverage (pure-Python vs. Rust results are checked against each
  other), alongside the existing ABNF meta-grammar fuzz.  Development
  tooling moved from black / isort to `ruff format`.

* `abnf` and `abnf-rust` release together at 2.6.0 from the same tag, as
  usual.  The Rust backend has no source changes this release; it is
  republished to keep the version-locked pair resolvable.

### Known issues

* The pure-Python `Repetition` parse cache is not invalidated when a
  grammar is mutated after it has been used to parse — via `=/`
  (incremental definition), rule redefinition, `Rule.exclude_rule`, or
  toggling `Rule.first_match_alternation`.  Re-parsing a previously-seen
  input can then return a stale result.  The bundled grammars are not
  affected (they are finalized at import, before any parse); only code
  that mutates a grammar after parsing with it is exposed.  A fix is
  planned for the next release.

## 2.5.1

* Migrate the `abnf-rust` bindings from pyo3 0.22 to pyo3 0.29.  This
  is an internal API migration only (the pyo3 `Bound` API rename:
  `from_value_bound` -> `from_value`, `import_bound` -> `import`,
  `downcast_into` -> `cast_into`); there is no change to the public
  API or to parser behavior in either package.

* Security / supply-chain hygiene: the pyo3 0.22 dependency shipped
  in `abnf-rust` 2.5.0 carried two RustSec advisories —
  RUSTSEC-2025-0020 (risk of buffer overflow in
  `PyString::from_object`) and RUSTSEC-2026-0177 (missing `Sync`
  bound on `PyCFunction::new_closure` closures).  `abnf-rust` never
  called either API, so prior releases were not exploitable through
  it; the bump to 0.29 clears both advisories so `cargo audit` and
  SBOM scanners report the dependency tree clean.

* The pure-Python `abnf` package has no source changes in this
  release.  It is republished at 2.5.1 only to keep the
  version-locked `abnf` / `abnf-rust` pair resolvable, since both
  publish together from the same `v*` tag.

## 2.5.0

* Add an optional Rust-backed parser engine.  Install via
  `pip install 'abnf[rust]'` to pull in the companion `abnf-rust`
  distribution; parses representative grammars 5-10x faster than the
  pure-Python backend.  Public API and semantics are unchanged.  The
  pure-Python backend remains the default and is always available as
  a fallback (force it with `ABNF_NO_RUST=1`).

* Internal refactor: the combinator engine has moved from
  `abnf.parser` to `abnf._parser_python`.  `abnf.parser` is now a
  dispatch shim that picks between the Python and Rust backends at
  import time.  All names re-exported by `abnf` are unchanged.  Code
  that monkey-patched internals via `abnf.parser` should now target
  `abnf._parser_python`.

* `abnf` and `abnf-rust` release together on the same `v*` git tag
  and are version-locked, so `pip install 'abnf[rust]'` always
  resolves to a matching pair.

* The Rust backend bounds rule-recursion depth, so left-recursive
  grammars raise `RecursionError` instead of overflowing the native
  stack.

* Latent bugs fixed: the pure-Python `Repetition` cache no longer
  accumulates traceback frames on a shared `ParseError` instance
  across cache hits; the Rust FFI returns code-point offsets (not
  byte offsets) for non-ASCII source in `Match.start` and
  `ParseError.start`; the Rust ASCII fast path honours full Unicode
  casefold expansion (so `Literal('ss', case_sensitive=False)`
  matches `'ß'` as in the Python reference); empty `Literal` no
  longer matches at end of source.

* Add `SECURITY.md` documenting how to report vulnerabilities.

* Pin every GitHub Actions reference to a commit SHA, document the
  minimal permissions each job needs, and add a zizmor workflow that
  audits the workflows on every change.  Both backends are now
  exercised in CI across Python 3.10-3.14.

## 2.4.1

* Add grammar for RFC 7239 (thanks to [alanverresen](https://github.com/alanverresen)).

* Claim support for python 3.14, drop support for python 3.9.

* Move dev dependency specifications to pyproject.toml; delete requirements-dev.txt.

* Remove twine, wheel from dev dependencies; bump versions of other dev packages to current versions.

* Enable dependabot checks.

## 2.4.0

* Add grammar for RFC 9051 (thanks to [iKoulee](https://github.com/iKoulee)).

* Bump setuptools from 75.6.0 to 78.1.1.

## 2.3.1

* This version contains no code changes.

* The contents of setup.cfg are now in pyproject.toml; setup.cfg and setup.py have been removed.

* Github codeql action is updated.

* Requirements.txt has been renamed to requirements-dev.txt to clarify that ABNF has no package dependencies.

* ABNF packages are now published to pypi using trusted publishing.

## 2.3.0

* A bit of work with cProfiler led to 7x improvement in parsing speed on grammars used to test parsing speed.

* abnf now supports python 3.9 - 3.13.

## 2.2.0

* Added RFC 9111.

* Removed changes to RFC 6266 grammar from https://www.rfc-editor.org/errata/eid5383, as that erratum
 has been rejected.

* RFC 3986 rule 'Host' now uses first-match alternation as specified.

* Rule.load_grammar now has an option 'strict' that specifies whether line endings in a source grammar
 are fixed.

## 2.1.0

* Added python 3.11 to tox.

* Added RFC 9110.
https://github.com/declaresub/abnf/issues/13

* Prose-vals that are really rulenames wrapped in angle-brackets are now parsed as rulenames and
become valid rules.
https://github.com/declaresub/abnf/issues/6

* Added RFC 3987.

* Rule.grammar can now be a string.  Another decorator load_grammar has been added to load such.

* RFC 7235 (now obsoleted by RFC 9110) no longer modifies the rule 'WWW-Authenticate', as the current parser correctly applies the rule as specified in the grammar.

* Modify grammar following an erratum to RFC 6266 to remove an ambiguity in the grammar.
https://github.com/declaresub/abnf/issues/16

* Implement RFC 6265 rule 'domain-value'.

## 2.0.2

* Repetition now correctly handles the case self.repeat.min == 0.  
https://github.com/declaresub/abnf/issues/15

* Concatenation objects no longer cache parse results.  This improves parsing performance significantly.

* Node, LiteralNode objects now use __slots__.

* Alternation.parse now yields matches as found.

## 2.0.1

* CharValNodeVisitor now visits a node generated by parsing "" correctly.
https://github.com/declaresub/abnf/issues/11

## 2.0.0

* Implement backtracking.  This is potentially a breaking change, given the changes to parsing behavior. 
https://github.com/declaresub/abnf/issues/4, https://github.com/declaresub/abnf/issues/10, https://github.com/declaresub/abnf/issues/11 .

* Add grammars for RFC 3339, 3629, 5987, 6266, 9116.

* Modify RFC 5322 rule ‘obs-unstruct’ following RFC errata.

## 1.2.1

* Fix a bug in Repetition class.  Refactoring to remove the use of a flatten function meant that matches
needed to be counted explicitly instead of using the size of the matched nodes list. https://github.com/declaresub/abnf/issues/10

* Add more type hints, and a py.typed file.

## 1.2.0

* Add type hints.

* add RFC 7489 grammar (thanks to egobiah).

## 1.1.1

* Imported rules are now created using the source rule's definition, instead of setting the
target rule definition to the source rule.  This was resulting in parse node trees with
unexpected structure.

* RFC 2735 credentials, challenge rules have been restored to their original definitions
now that longest match alternation is the default.

## 1.1.0

* Added class method Rule.from_file which loads a grammar from an ABNF rulelist in a file. https://github.com/declaresub/abnf/issues/2

* Added class attribute Rule.first_match_alternation.  When false, alternation returns the longest 
match, with ties broken by order of match.  When True, alternation returns the first match.

* Added Rule.exclude_rule.  This object method allows one to restrict an existing rule by
excluding values that match another rule.  The initial use case was to exclude keywords
from matching identifiers.

* Parsing is generally faster following some internal tinkering and refactoring.


## 1.0.1

* Unicode characters > 127 expressed as num-val are now correctly parsed. https://github.com/declaresub/abnf/issues/1


## 1.0.0

* Initial release.
