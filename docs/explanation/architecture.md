# Architecture: parser combinators

abnf is implemented with **parser combinators**. Primitive parsers are composed
into complex ones, and the composition mirrors the structure of the grammar.

The base primitive is `Literal`, whose instances are initialized with either a
string like `'moof'` or a two-element tuple like `('a', 'z')` representing an
inclusive range. The result is a parser that matches the initialized value.

The ABNF operations — alternation, concatenation, repetition, optional groups —
are each implemented as a class. For example,

```python
Alternation(Literal("foo"), Literal("bar"))
```

returns a parser implementing the ABNF expression `"foo" / "bar"`. `Concatenation`,
`Repetition`, `Option`, and `Prose` fill out the set. Each combinator exposes an
`lparse(source, start)` method — a generator that yields the matches it finds at
`start`. Composing combinators composes their generators, and the parse tree of
`Node` objects falls out of that composition.

A `Rule` ties a name to a combinator tree and maintains a per-subclass registry of
named rules, so rules can refer to one another by name (including across grammar
modules).

## Bootstrapping

The parser bootstraps itself. The RFC 5234 core rules and the ABNF meta-grammar are
constructed directly from the combinator classes in code — there is no parser yet
to read them from text. `ABNFGrammarRule` holds the resulting meta-grammar: it is
the parser used to read *every other* grammar, and it can parse its own ABNF source
as a self-check.

This is why you can hand `Rule.create` a string of ABNF and get back a working
parser: `ABNFGrammarRule` parses that ABNF text into a parse tree, and a
`NodeVisitor` walks the tree to build the corresponding combinator objects.

## Working with parse trees

Parsing yields a tree of `Node` objects (with `LiteralNode` leaves). The usual way
to extract data is a `NodeVisitor` subclass whose `visit_<rulename>` methods are
dispatched reflectively as the tree is walked — see
{doc}`../how-to/extract-values-with-visitors`.
