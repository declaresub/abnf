# API reference

The public API is exported from the top-level `abnf` package:

```python
from abnf import Rule, Node, LiteralNode, NodeVisitor, Parser, ParseError, GrammarError
```

The parser combinator primitives (`Alternation`, `Concatenation`, `Repetition`,
`Option`, `Literal`, `Prose`) are internal and not part of the public API; see
{doc}`../explanation/architecture` for how they fit together.  `Parser` is the
protocol they satisfy, exported for type hints rather than for instantiation.

## Rule

```{eval-rst}
.. autoclass:: abnf.Rule
   :members:
```

## Node

```{eval-rst}
.. autoclass:: abnf.Node
   :members:
```

## LiteralNode

```{eval-rst}
.. autoclass:: abnf.LiteralNode
   :members:
```

## NodeVisitor

```{eval-rst}
.. autoclass:: abnf.NodeVisitor
   :members:
```

## Parser

```{eval-rst}
.. autoclass:: abnf.Parser
   :members:
```

A [protocol](https://docs.python.org/3/library/typing.html#typing.Protocol), not
a base class: anything with a compatible `lparse` satisfies it, including the
combinators, `Rule`, and a parser you write yourself.  Use it to annotate code
that accepts or returns a parser.

```python
from abnf import Parser


def wrap(inner: Parser) -> Parser:
    ...
```

It is `runtime_checkable`, so `isinstance(obj, Parser)` works too — bearing in
mind that this checks only for the presence of `lparse`, not its signature.

## Exceptions

```{eval-rst}
.. autoexception:: abnf.ParseError

.. autoexception:: abnf.GrammarError

.. autoexception:: abnf.GrammarWarning
```

`ParseError.start` is the code-point offset where the parse failed, and is
identical on both backends.

`ParseError.parser` describes what failed, but *how* it describes it depends on
the backend: the pure-Python implementation stores the parser object itself,
while the Rust backend stores a description string such as `"Concatenation"` or
`"Literal('a')"`. The engine builds an error on every failed alternative, so it
carries a description prepared once at construction rather than a reference to
the parser — which is what keeps backtracking cheap.

Treat `parser` as diagnostic output: `str(exc)` and logging work on both
backends, and `exc.start` is the attribute to branch on. Code that reaches into
it, such as `exc.parser.name`, works only under the pure-Python backend.
