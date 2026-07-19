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
