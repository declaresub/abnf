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
