# Changelog

## Unreleased

* `abnf.grammars.rfc7489` accepts the DMARC records RFC 7489 defines, including
  the one printed in the RFC's own section B.1.1.  `dmarc-record` required the
  `p` tag and a trailing `";"`, both of which section 6.4 brackets as optional,
  so `v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com` was rejected --
  as is most of what is published, since records rarely end in a separator.
  The rule keeps reading the RFC's fixed sequence as a repetition, which is
  what its own note about components appearing "in any order" calls for
  (https://github.com/declaresub/abnf/issues/233).

  The `URI` rule, which this module deliberately narrows to the mailto scheme
  (section 6.2 supports no other), is now written as a char-val rather than as
  `%x` literals, so it is case-insensitive as RFC 3986 section 3.1 requires of
  a scheme.  `MAILTO:` used to be rejected.

* `abnf.grammars.rfc3986` and `abnf.grammars.rfc3987` accept URIs and IRIs they
  used to reject.  `host` set `first_match_alternation`, citing RFC 3986
  section 3.2.2 -- but that section is about attributing a match of the *whole*
  host, while first match commits to `IPv4address` on a **prefix**.  Given
  `http://1.2.3.4.5/`, `IPv4address` matched `1.2.3.4`, `reg-name` was never
  tried, and the URI was rejected; so was any host of the shape
  `1.2.3.4.in-addr.arpa`, which is an ordinary reverse-DNS name.  `rfc3987`
  applied the same setting to every rule in the module, in a loop.

  Nothing is lost by removing it: longest-match alternation already attributes
  a full IPv4 host to `IPv4address` rather than `reg-name`, because the two tie
  and the tie is broken by declaration order -- which is exactly what section
  3.2.2 asks for.  Across a 48-case corpus the only changes are five
  rejections becoming acceptances; no input that already parsed changes its
  value or its parse tree (https://github.com/declaresub/abnf/issues/232).

* `Node`, `LiteralNode` and `Match` can be subclassed under the Rust backend,
  as they always could under the pure-Python one.  The pyclasses were final,
  so `class MyNode(Node)` raised `TypeError` -- against a how-to that says
  installing the extension changes nothing in your code
  (https://github.com/declaresub/abnf/issues/221).

* `Repeat` accepts the values the pure-Python constructor accepts.  A negative
  `min` is not an error there -- the repetition simply builds no mandatory
  prefix, so it behaves as zero -- and a float `max` is compared against the
  repetition count, so a non-integral one never caps and an integral one caps
  where the integer would.  Both now behave the same on either backend.  The
  stored attributes can still differ for such inputs (a negative `min` reads
  back as `0`), but no input reaches either bound, so nothing observable
  follows from it.  The genuine errors are unchanged: `3*2` and a negative
  `max` raise `GrammarError`, a non-number raises `TypeError`.

* Document that mutating `node.children` or `match.nodes` is not supported, and
  what each backend does if you try: the pure-Python containers are live lists,
  while the Rust ones are rebuilt per access, so the change is dropped.  Making
  the Rust getters return tuples would raise instead of vanishing, but a tuple
  stops comparing equal to a list -- breaking reading code to fix writing code
  that should not exist.  A parse tree is meant to be read
  (https://github.com/declaresub/abnf/issues/221).

* A value returned by a custom parser is no longer replaced by source text.
  Since 2.8.1 the engine's terminals are spans of the source and their values
  are produced by slicing it, which is sound for nodes the engine builds --
  but a node handed *in* by a parser you write need not correspond to any
  span.  Returning a normalised or synthesised value is a legitimate thing to
  do, and the pure-Python backend keeps it; the Rust backend silently
  substituted whatever text sat at that offset.  Such nodes now carry their
  own value across the boundary, as code points, so a surrogate survives too
  (https://github.com/declaresub/abnf/issues/220).

  Parse performance is unaffected: the new node kind is behind an `Arc`, as
  `Node`'s children already were.  Holding it inline, or behind a `Box`, cost
  5-9% on the benchmarks -- node lists are cloned on every match extension, so
  the variant's size and its clone land on every parse whether or not a
  grammar ever produces one.

* Document that `ParseError.parser` holds the parser object under the
  pure-Python backend and a description string under the Rust one.  `start`
  means the same thing either way, and is the attribute to branch on; `parser`
  is diagnostic output, and reaching into it (`exc.parser.name`) is portable
  only to pure Python.  The engine builds an error on every failed
  alternative, so it carries a description prepared once at construction
  rather than a reference to the parser, which is what keeps backtracking
  cheap (https://github.com/declaresub/abnf/issues/219).

## 2.8.3

* A reference to a rule that was never defined now raises `GrammarError` on the
  Rust backend, as it already did on the pure-Python one.  It was an ordinary
  `ParseError`, which is indistinguishable from "this alternative did not
  match", so an enclosing `Alternation` or `Repetition` swallowed it as
  backtracking: given `a = b / "x"` with `b` undefined, the Rust engine matched
  `"x"` and silently dropped the `b` branch, while pure Python raised.  A typo'd
  rule name quietly narrowed the grammar rather than reporting a problem.

  The identical defect was fixed for exclusions in 2.8.1; the plain definition
  lookup one screen below it in `rule.rs` was missed
  (https://github.com/declaresub/abnf/issues/201).

* A custom parser that re-enters the engine on a *different* source no longer
  corrupts the enclosing parse.  Memoisation is scoped by epoch and keyed by
  position alone, so an epoch may only ever see one source; nested entries
  shared the enclosing parse's epoch, on the reasoning that a callback
  re-entering the engine is part of the same parse.  The `Parser` protocol is
  public, though, and a parser you write may parse anything while it runs --
  after which entries made against the inner source answered lookups against
  the outer one, and the outer parse returned a wrong result.  The pure-Python
  backend was never affected: its memo carries the source and checks identity
  before use.

  The FFI boundary now compares the `str` object's identity, as the
  pure-Python memo does, and gives a genuinely different source its own epoch.
  Same-source re-entry keeps sharing, which matters because an epoch change
  resets the caches it touches -- claiming one unconditionally would wipe the
  enclosing parse's memo on every callback
  (https://github.com/declaresub/abnf/issues/202).

* A custom parser reporting a match that ends past the end of the source no
  longer panics when the enclosing rule has an exclusion.  The exclusion check
  sliced the source with that offset, and the offset comes from Python, so it
  was never validated.  A panic crosses the FFI as `PanicException`, which
  derives from `BaseException` -- so `except ParseError`, and even `except
  Exception`, failed to catch it, and a Rust panic banner went to stderr.
  Text that is not in the source cannot be text the excluded rule matches, so
  a nonsensical span is now treated as "not excluded"; the bad offset then
  fails naturally further up, exactly as it does on the pure-Python backend
  (https://github.com/declaresub/abnf/issues/218).

* A duck-typed parser that happens to have a `name` attribute is no longer
  mistaken for a `Rule` by the Rust backend.  Parsers were identified by
  attribute shape -- anything with `name` and `lparse` -- so such an object
  became a definition-less `NamedRule` and its own `lparse` was never called:
  `Concatenation(Literal("x"), MyParser())` matched `"xz"` on the pure-Python
  backend and failed on the Rust one, controlled by an attribute that looks
  incidental.

  It also entered the bridge, a registry keyed by the Python object's
  *address*.  That is sound for rules, which `Rule._obj_map` keeps alive
  forever, but not for an arbitrary user object: a freed one's address could
  be handed to a new `Rule`, which then inherited its stale handle.
  Reproduced -- defining such a rule wrote into a parser tree built from an
  unrelated object, and the tree matched input the original parser always
  rejected.

  Rules are now identified by type.  Everything else with `lparse` takes the
  callback path, which holds a reference to the object, so it cannot dangle
  (https://github.com/declaresub/abnf/issues/203).

* Four small divergences between the backends, each resolved toward the
  pure-Python implementation (https://github.com/declaresub/abnf/issues/204):

  * A repeat bound too large for a machine word saturates rather than raising
    `OverflowError`.  Python's ints are unbounded, so `2*99999999999999999999`
    is odd but valid ABNF the pure-Python backend parses happily -- the bound
    is never reached -- and `OverflowError` is neither `GrammarError` nor
    `ParseError`, so it escaped the documented exception contract too.  Such a
    bound reads back from `Repeat.max` as the machine maximum under the Rust
    backend; no input can reach either value, so matching is unaffected.
  * `Literal(('a', 'z')).case_sensitive` reads `False` rather than `True`.  A
    range compares by code point either way, so this was the attribute alone.
  * `Node` equality is structural -- name and children, compared recursively
    -- rather than a comparison of concatenated values, which called two
    different parse trees equal whenever they spanned the same text.  It
    silently changed what a user's assertions meant depending on which backend
    was installed.
  * `LiteralNode` is unhashable, as it is in pure Python, where defining
    `__eq__` without `__hash__` makes it so.  `Node` was already unhashable on
    both, so no parse-tree node is hashable anywhere.

## 2.8.2

* Fix `import abnf` crashing when `abnf-rust` is older than `abnf`.  The
  dispatch shim reached for `set_exclude_hook` -- added to the extension in
  2.8.1 -- outside the `try/except ImportError` that guards backend selection,
  and `AttributeError` is not an `ImportError`, so the documented fallback to
  the pure-Python backend never happened.  `abnf` 2.8.1 with `abnf-rust` 2.7.0
  was a combination the dependency floor allowed, and it died on import.

  `abnf.parser` now checks that the extension provides everything it binds
  before committing to it, and falls back with a `RuntimeWarning` naming what
  is missing.  `BACKEND_READY` could not answer this: it is a static flag
  meaning "this build finished", which an older extension sets too.

  The `[rust]` extra's floor is raised to `abnf-rust>=2.8.1` as well.  The
  bound is necessary but not sufficient -- it can only name a version already
  published when the release is built, so it lags by one release, and it is
  advisory for lockfile installs -- which is why the runtime check carries the
  guarantee (https://github.com/declaresub/abnf/issues/199).

## 2.8.1

*2.8.0 was tagged but never published: its release build failed before either
package reached PyPI, and `v*` tags are immutable, so the fix ships under a new
version.  Nothing was ever available at 2.8.0.*

* **Behaviour change.**  Case-insensitive literal matching now folds case over
  US-ASCII only, per RFC 5234 §2.3, which fixes the character set for literals
  as US-ASCII.  Previously both backends folded the full Unicode range
  (`str.casefold()` in Python, the `caseless` crate in Rust), which accepted
  input outside the character set the grammar was written in: `%x212A` (KELVIN
  SIGN) matched a `"k"` in a literal and `%x017F` (LATIN SMALL LETTER LONG S)
  matched an `"s"`, so RFC 7230 accepted `compre\u017f\u017f` as a
  transfer-coding.  Against a peer folding only ASCII, that is a parser
  differential.  ASCII folding is also length-preserving, which removes a
  position dependence: `Literal("ss", case_sensitive=False)` matched a lone
  `'ß'` but not the `'ß'` in `'ßx'`.  Literals containing non-ASCII characters
  still match themselves exactly; case-sensitive matching is unaffected, as is
  the case-insensitive lookup of *rule names*, which continues to use full
  folding on both backends.

* `first_match_alternation` now reaches alternations nested inside a group or
  repetition, whether set grammar-wide or on a single rule.  Both forms were
  broken: as a class attribute it shadowed the property of the same name and
  nothing read it, so it did nothing at all; set on a rule it flipped only that
  rule's top-level `Alternation`, so `a = "a" ( "b" / "bc" )` and
  `iuserinfo = *( iunreserved / pct-encoded / sub-delims / ":" )` could not be
  configured -- the assignment was silently dropped, and reading the attribute
  back returned `False`.  The alternations are now recorded as each rule is
  built, which is the only approach open to both backends: the Rust
  combinators expose no children, so the tree cannot be walked afterwards
  (https://github.com/declaresub/abnf/issues/53).

  Two consequences worth noting.  A grammar that sets the class attribute
  today gets first-match semantics it was asking for but not receiving --
  `abnf.grammars.rfc3987` sets it on every rule, and its parse results are
  unchanged, because its alternatives are disjoint on their first character.
  And setting the flag on a rule with no alternation stays a no-op rather than
  raising: the grammar is valid, the same flag set grammar-wide covers many
  such rules, and a single-alternative rule collapses to its element, so
  raising would make the call brittle under ordinary edits.  Setting it on an
  undefined rule still raises `GrammarError`.

  The attribute is a descriptor rather than a property, so that the documented
  spelling type-checks: assigning a `bool` in a subclass body is an
  incompatible override of a `property`, which pyright rejects in user code.

* The Rust engine represents the source as **code points** rather than as
  `&str`, which fixes the last behavioural difference between the two backends.
  It previously worked in `char` and `&str` -- Unicode *scalar values* and
  well-formed UTF-8 -- and neither can hold a surrogate, so `%xD800-DBFF`
  failed to load as a grammar and input containing a lone surrogate failed to
  cross the FFI with a `UnicodeEncodeError`.  That is ordinary input:
  `surrogateescape` is how Python represents undecodable filenames, `sys.argv`
  and environment variables, and an unpaired `\uD800` survives `json.loads`, so
  a program that worked on the pure-Python backend broke when its user
  installed `abnf[rust]` for speed.  Both now parse identically
  (https://github.com/declaresub/abnf/issues/173).

  Two consequences beyond the fix.  Offsets need no translation at the
  boundary any more -- the engine counts in the same unit Python `str` indices
  do -- so the byte/code-point conversion is gone, along with a `source
  .is_ascii()` scan that ran *once per parse-tree node* and made a long ASCII
  source O(nodes x length): a 1 MiB ASCII source with a small parse drops from
  1146 to 142 us.  Against that, widening the source is now O(n) up front, so
  the same shape over a 1 MiB *non-ASCII* source rises from 41 to 142 us, and
  peak memory during a parse includes 4 bytes per code point.  The bundled
  benchmarks, which parse realistic inputs, are 3-8% faster.

  Node values are Python strings sliced from the caller's own source rather
  than rebuilt in Rust, which is what lets a value hold a surrogate.  This
  relies on a node's value always being a contiguous span of the source --
  checked here over 2.6 million nodes across the test corpus.

* Export `Parser` from the top-level `abnf` package.  It is the protocol the
  combinators satisfy, and it is useful for annotating code that accepts or
  returns a parser -- which meant reaching into `abnf.parser` for it.  Being a
  `Protocol`, it describes a shape rather than a base class: `Rule`, the
  built-in combinators (including the Rust-backed ones) and a parser you write
  yourself all satisfy it without inheriting anything
  (https://github.com/declaresub/abnf/issues/17).

* Remove `abnf_rust._ext.clear_bridge()`, a private diagnostic that emptied the
  Rust engine's rule registry.  It could not do its job and broke correctness in
  the attempt: a rule's compiled tree embeds the handles of the rules it
  references, so clearing the registry frees very little, while every grammar
  defined afterwards gets fresh empty handles for `ALPHA`, `DIGIT` and friends
  and silently rejects valid input.  Redefining a rule after a clear was
  silently lost, too.  The registry's growth is documented instead, with the
  measured cost on both backends, and the note now points at the lever that
  actually works -- caching the `Rule` subclass for a grammar rather than
  rebuilding it (https://github.com/declaresub/abnf/issues/187).

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

* `Rule.exclude` is now a property whose setter notifies the backend, mirroring
  `Rule.definition`, and `Rule.exclude_rule` is a thin wrapper over it.  Only the
  method used to notify, so on the Rust backend `rule.exclude = None` cleared the
  exclusion for the pure-Python parser while the engine went on applying it, and
  assigning `rule.exclude = other` was ignored entirely.  Assignment is the only
  way to *remove* an exclusion, so that was the case most likely to be hit.

* An exclusion naming a rule that has no definition now raises `GrammarError` on
  both backends.  The Rust engine treated the missing definition as an ordinary
  parse failure -- "not excluded" -- and accepted input the grammar was written
  to reject.

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

* `NodeVisitor` computes its `visit_*` dispatch table once per class instead of
  rebuilding it from `dir(self)` on every instantiation.  `dir()` walks the whole
  MRO and sorts the result, which is a lot of work to repeat for an answer that
  depends only on the class: constructing `ABNFGrammarNodeVisitor` drops from
  13.8 to 3.2 us, a three-method user visitor from 3.6 to 0.7 us, and
  `Rule.create` -- which builds one per call -- is about 4% faster.  Parsing then
  walking a tree with a fresh visitor is ~15% faster end to end on the Rust
  backend for a short input, where the visitor was a real share of the work; on
  the pure-Python backend parsing dominates and the difference does not show.

  Behaviour is unchanged, including the dynamic cases: `visit_*` set as instance
  attributes are still found (`ABNFGrammarNodeVisitor` relies on this), and
  methods added to or removed from a class after it has been instantiated still
  take effect, via a cheap check that costs ~240ns against the ~3.1us scan it
  guards.

* `Match` no longer memoises its hash, and `Match.__eq__` compares values rather
  than hashes.  Nothing in the parser hashes or compares a `Match` -- both
  `Repetition` and `Rule.lparse` deduplicate by end offset -- so the cached slot
  cost eight bytes on every match built, a few thousand per parse, to speed up
  an operation the library never performs.  It also could not be invalidated:
  `nodes` is a plain mutable list, so the memo went stale as soon as a caller
  touched it.  `Match` is now 48 bytes rather than 56.

  Comparing hashes meant two matches whose hashes collided compared equal;
  `__eq__` now compares the text directly, which is the one place that has to be
  exact.  Equality semantics are unchanged otherwise: matches are equal when
  they consumed the same text and ended at the same offset, whatever node
  structure produced it.  Hashing a `Match` repeatedly is ~4x slower without the
  memo; parse times are unaffected.

* The pure-Python `Repetition` stores its match list already sorted, so a memo
  hit iterates it directly instead of copying and re-sorting a list that cannot
  have changed.  A cold `rfc5322` mailbox parse takes ~1,700 such hits and is
  about 5% faster as a result (median 5720 -> 5413 us).  Grammars that do not
  backtrack are unaffected -- they get no memo hits at all -- so the other
  benchmark workloads are unchanged.  Yield order is identical, verified by
  fingerprinting the full ordered match sequence over 600 parses before and
  after.  The Rust engine already worked this way.

* The Rust engine builds a repetition's mandatory-prefix parser once, at
  construction, rather than rebuilding it on every cache miss.  `1*X` is the most
  common repetition in any grammar, and each miss allocated a `Vec` plus a
  `Concatenation` that depended only on values fixed when the `Repetition` was
  created.  The pure-Python backend was fixed the same way earlier in this
  release; this brings the two into line.  No measurable speed change -- for
  `min = 1` the discarded allocation is one `Arc` clone and a one-element `Vec`,
  which does not register against the parsing work at any input size tested.

* The parse benchmarks now measure a cold parse per iteration, because there is
  no longer a cross-call cache for later iterations to hit.  Numbers published
  before this change measured cache hits and are not comparable.

* Document the Rust engine's rule registry and how it grows in a long-running
  process: 40 entries after `import abnf`, 1,176 with all bundled grammars
  loaded, and one more per rule created at runtime, at roughly 1.6 KiB each.
  A fixed cost for the ordinary import-once case; it accumulates only for
  processes that build grammars per request or in a loop.  The pure-Python
  `Rule._obj_map` grows the same way, so this is not specific to the Rust
  backend.  The note also warns against `abnf_rust._ext.clear_bridge()`, a
  private diagnostic that silently breaks any grammar defined after it runs
  (https://github.com/declaresub/abnf/issues/187).

* Document `Rule.exclude_rule`.  Its docstring was reachable in the API
  reference, but nothing in the guides mentioned it, so the answer to "how do I
  say an identifier that is not a keyword?" -- a thing ABNF has no operator for
  -- was undiscoverable.  New how-to covering the recipe, the complete-match
  semantics, and the fact that it filters candidate matches rather than aborting
  the parse.

* Tests for RFC 3986's `path` rule, and a documented caveat about first-match
  alternation.  `path` lists `path-abempty` first, and that alternative matches
  the empty string, which looks like it should swallow every input.  It does
  not under the default longest-match semantics, and the grammar is left as the
  RFC writes it; the tests pin that, along with the cases where `path-empty` is
  genuinely reached (`hier-part` and `relative-part` of an empty path, as in
  `mailto:`).  Under `first_match_alternation = True` the concern is real --
  `path` then matches nothing at all -- so the alternation docs now warn that an
  alternative which can match empty makes everything after it unreachable, which
  is why first match is not a drop-in switch for a grammar transcribed from an
  RFC (https://github.com/declaresub/abnf/issues/24).

* Raise the `[rust]` extra's floor to `abnf-rust>=2.7`, and check in CI that
  the runtime dependency closure still resolves.  The floor can only name a
  version already on PyPI: the release workflow resolves this dependency to
  build the SBOM, before anything is published, so naming the version being
  released makes the release unbuildable.  Nothing outside a tag build
  exercised that resolution, so CI now runs the same command on every pull
  request, along with `uv lock --check`.

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

### Known issues

* `Rule.exclude_rule` is silently ignored for nested rule references under the
  Rust backend: the exclusion is implemented in the pure-Python `Rule.lparse`,
  which the Rust path enters only for the top-level rule.  A grammar written to
  reject a keyword will accept it.  `ABNF_NO_RUST=1` is a correct workaround.
  https://github.com/declaresub/abnf/issues/179

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
