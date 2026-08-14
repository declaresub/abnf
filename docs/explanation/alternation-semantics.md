# Alternation: longest match vs. first match

RFC 5234 does not specify the precise behavior of alternation. The ABNF definition
of ABNF appears to assume **longest match**, but other grammars expect **first
match** — for example, [Dhall](https://dhall-lang.org). abnf therefore makes the
behavior configurable per grammar.

The class attribute `Rule.first_match_alternation` selects the behavior for a
particular grammar (represented by a `Rule` subclass):

- **`False`** (default) — alternation returns the **longest** match. In the event
  of a tie, the **first** match (by declaration order) is returned.
- **`True`** — the **first** matching alternative is returned.

```python
from abnf import Rule

class FirstMatchGrammar(Rule):
    first_match_alternation = True
```

## Why it matters

Consider `astring = 1*ASTRING-CHAR / string`. Under longest-match semantics, the
parser must try both arms and compare — it cannot commit to `1*ASTRING-CHAR` until
it knows `string` would not have matched more. Under first-match semantics, the
first arm that succeeds is taken immediately, which is cheaper but can change which
parse tree you get for an ambiguous grammar.

Choosing longest match is what makes abnf faithful to RFC grammars out of the box;
choosing first match lets you model PEG-like grammars that depend on ordered
choice. The trade-off in cost is discussed in {doc}`backtracking-and-caching` and
{doc}`rust-backend-performance`.

## Watch out for alternatives that can match nothing

Under first match, an alternative that can match the empty string wins as soon as
it is tried — and it is tried in declaration order, not in order of how much it
consumes. Any alternative after it becomes unreachable.

RFC grammars are written this way regularly, because their authors assumed
longest match. RFC 3986 is a good example:

```text
path        = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty
path-abempty = *( "/" segment )          ; matches "" quite happily
```

Under the default, `path` parses `a/b/c` as `path-noscheme` and consumes all of
it. Set `first_match_alternation = True` and the same rule returns an empty
match, because `path-abempty` is listed first and succeeds immediately
([issue #24](https://github.com/declaresub/abnf/issues/24)).

So first match is not a drop-in speedup for a grammar transcribed from an RFC.
Enable it for a grammar written with ordered choice in mind, or per rule where
you have checked the alternatives — `abnf.grammars.rfc3986` does the latter for
`host`, where the RFC's own order is the intended one.
