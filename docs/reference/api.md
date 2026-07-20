# API reference

The public API is exported from the top-level `abnf` package:

```python
from abnf import Rule, Node, LiteralNode, NodeVisitor, ParseError, GrammarError
```

The parser combinator primitives (`Alternation`, `Concatenation`, `Repetition`,
`Option`, `Literal`, `Prose`) are internal and not part of the public API; see
{doc}`../explanation/architecture` for how they fit together.

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

## Exceptions

```{eval-rst}
.. autoexception:: abnf.ParseError

.. autoexception:: abnf.GrammarError

.. autoexception:: abnf.GrammarWarning
```
