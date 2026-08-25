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

## You cannot redefine a core rule

The RFC 5234 appendix B core rules — `ALPHA`, `BIT`, `CHAR`, `CR`, `CRLF`,
`CTL`, `DIGIT`, `DQUOTE`, `HEXDIG`, `HTAB`, `LF`, `LWSP`, `OCTET`, `SP`,
`VCHAR`, `WSP` — live on the base `Rule` class so that every grammar can use
them without declaring them. Reference them freely:

```python
R.create("pair = DIGIT ALPHA")
```

Defining one is refused, because there is only one of each and it is shared:

```python
R.create('DIGIT = %x30-39 / "_"')
# GrammarError: 'DIGIT' is a core rule from RFC 5234 appendix B, shared by every
# grammar, so a grammar cannot define it ...
```

Without that check the definition replaced `DIGIT` for *every* grammar in the
process. A config-format grammar allowing `1_000` made `abnf.grammars.rfc3339`
accept `2_26` as a four-digit year
([issue #256](https://github.com/declaresub/abnf/issues/256)).

Older RFCs — RFC 2616 section 2.2 among them — restate these rules in their own
text. Leave those lines out when you transcribe: the core rules are already
there, and the ones those RFCs define are the same rules.

```{warning}
You can change a core rule for everything by defining it on the base class:

    from abnf.parser import Rule
    Rule.create('DIGIT = %x30-39 / "_"')

This is almost never a good idea. It rewrites the rule for every grammar in the
process, including the bundled ones and any library that imports them, and
nothing downstream has a way to opt out. It is allowed because it is explicit
about doing so — a grammar module cannot reach this by accident — and it emits
a `GrammarWarning`. Prefer a differently named rule of your own.
```

## Left recursion will not work

`abnf` is a recursive-descent parser, so a rule that can reach itself in
leftmost position has no base case to reach: it recurses until the stack runs
out. The failure is reported as a `ParseError`, which makes it look like the
input was wrong.

```text
list = item / list "," item          ; do not write this
```

Under longest-match alternation — the default — this is worse than it looks.
Every alternative is evaluated, so the recursive one is always reached, and the
rule matches **nothing at all**, not even the plain `item` that its own first
alternative admits.

```python
Rule("list").parse_all("a")          # ParseError, despite `item` matching
```

Rewrite it to the right-recursive form, which describes the same language:

```text
list = item *("," item)
```

Where the repeated part is more than one element, hoist it into its own rule:

```text
comp      = comp-item *(SP comp-item)
comp-item = astring / "(" comp ")"
```

RFCs do write left-recursive rules — RFC 9051 has two, which is
[issue #252](https://github.com/declaresub/abnf/issues/252) — so transcribing a
grammar faithfully is not sufficient. If a rule of yours refuses everything
including its own simplest alternative, this is the first thing to check.

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

### An import replaces a rule of the same name

Imports are applied *after* the grammar text, so importing a name your own
grammar defines replaces your definition with the other module's. That is
deliberate — it is how a module declares a rule it does not own and lets the
import supply it:

```text
token = <token, see [HTTP], Section 5.6.2>        ; filled in by the import
```

Replacing anything *other* than a prose placeholder is almost always an
accident, and `abnf` warns about it:

```python
importing "atom" from rfc5322 overwrites the definition rfc9051 declares for it.
```

The warning is a `GrammarWarning`. Turn it into an error while developing a
grammar with `warnings.simplefilter("error", GrammarWarning)`.
