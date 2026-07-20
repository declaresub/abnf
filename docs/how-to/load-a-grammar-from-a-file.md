# Load a grammar from a file

To keep a grammar in a separate `.abnf` file, define an empty `Rule` subclass and
populate it with `from_file`, which accepts a `str` path or a `pathlib.Path`. The
file must contain an ABNF *rulelist*.

```python
from abnf import Rule

class MyGrammar(Rule):
    pass

MyGrammar.from_file("grammar.abnf")

MyGrammar("my-top-rule").parse_all("some input")
```

Given a `grammar.abnf` like:

```abnf
greeting = "hello" SP name
name     = 1*ALPHA
```

`MyGrammar("greeting").parse_all("hello world")` succeeds. The core rules (`SP`,
`ALPHA`, …) are available without redefinition — see {doc}`../reference/core-rules`.

```{warning}
ABNF uses CRLF (`\r\n`) to delimit rules in a rulelist. Many text editors silently
rewrite line endings on save (BBEdit is one), which can quietly break a grammar
file. `from_file` opens the file expecting CRLF; if you build grammar text in
memory instead, use `Rule.load_grammar`, which normalizes line endings for you by
default.
```

To load grammar text you already have in a string, use `Rule.create` (one rule) or
`Rule.load_grammar` (a rulelist) — see {doc}`write-your-own-grammar-module`.
