# Write your own grammar module

A `Rule` subclass corresponds to a grammar; instances of the subclass are the rules
of that grammar. There are a few ways to populate one.

## A single rule with `create`

```python
from abnf import Rule

rule = Rule.create(
    'double-quoted-string = DQUOTE *(%x20-21 / %x23-7E / %x22.22) DQUOTE'
)
```

Retrieve it later by name (rule objects are cached, so this returns the same
object):

```python
rule = Rule("double-quoted-string")
```

## A whole grammar with `load_grammar`

For several rules at once, subclass `Rule` and call `load_grammar` with a rulelist:

```python
from abnf import Rule

class Postal(Rule):
    pass

Postal.load_grammar(
    """
    address   = name street zip
    name      = 1*ALPHA
    street    = 1*(ALPHA / DIGIT / SP)
    zip       = 5DIGIT
    """
)
```

`load_grammar` normalizes line endings to CRLF by default. Use a subclass (rather
than the base `Rule`) so your rules live in their own registry and cannot collide
with another grammar's.

## Importing rules from another module

Real RFC grammars reuse rules from other RFCs. The bundled grammars do this with the
`@load_grammar_rules([...])` decorator, passing `(name, rule)` pairs to import.
`abnf.grammars.rfc7240` is a compact example — it pulls `token`, `quoted-string`,
`OWS`, and `BWS` in from `rfc7230`:

```python
from typing import ClassVar

from abnf.parser import Rule as _Rule
from abnf.grammars import rfc7230
from abnf.grammars.misc import load_grammar_rules

@load_grammar_rules(
    [
        ("token", rfc7230.Rule("token")),
        ("quoted-string", rfc7230.Rule("quoted-string")),
        ("OWS", rfc7230.Rule("OWS")),
        ("BWS", rfc7230.Rule("BWS")),
    ]
)
class Rule(_Rule):
    grammar: ClassVar[list[str] | str] = [
        'Prefer = "Prefer" ":" OWS preference *( OWS "," OWS preference )',
        'preference = token [ BWS "=" BWS word ] *( OWS ";" [ OWS parameter ] )',
        'parameter = token [ BWS "=" BWS word ]',
        "word = token / quoted-string",
    ]
```

The imported rules are stitched into the subclass's registry at class-definition
time, so `Rule("preference")` can reference `token` and `OWS` as if they were
defined locally. Browse `abnf.grammars` for more patterns, and see
{doc}`../reference/bundled-grammars` for the full list.
