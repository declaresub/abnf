# Parse your first header

This tutorial walks you from an empty environment to parsing a real HTTP header,
inspecting the result, extracting a value from it, and finally writing a tiny
grammar of your own. It should take about ten minutes. You don't need to know
anything about ABNF or parser theory — just follow along, and by the end you'll
have run every core piece of the library.

## 1. Install abnf

In a fresh virtual environment:

```console
pip install abnf
```

Check it imported:

```python
import abnf
print(abnf.__version__)
```

## 2. Parse a header with a bundled grammar

abnf ships with grammars for many RFCs. We'll use the one for HTTP conditional
requests (RFC 7232) to parse an `ETag` header value. Open a Python prompt and run:

```python
from abnf.grammars import rfc7232

node, offset = rfc7232.Rule("ETag").parse('W/"moof"', 0)
```

`rfc7232.Rule("ETag")` is the parser for the `ETag` rule. Its `parse` method takes
the input string and a starting offset, and returns two things: the **parse tree**
(`node`) and the **offset** just past what it matched. Check that it consumed the
whole string:

```python
print(offset)          # 8, the length of 'W/"moof"'
```

Congratulations — you've parsed your first header.

## 3. Look at the parse tree

The tree records exactly how the input matched the grammar. Every node has a `name`
(the rule it came from) and a `value` (the text it matched):

```python
print(node.name)       # 'ETag'
print(node.value)      # 'W/"moof"'
```

Nodes have children, mirroring the grammar's structure. The `ETag` rule is defined
(in RFC 7232) as `entity-tag`, which is an optional `weak` marker followed by an
`opaque-tag`. You can see that shape by walking the children:

```python
for child in node.children:
    print(child.name, "->", repr(child.value))
```

Print the whole tree if you're curious — `str(node)` renders it in full:

```python
print(str(node))
```

## 4. Extract a value

Usually you don't want the whole tree — you want one piece of it. Here's a small
breadth-first search that finds the first node with a given rule name and returns
its matched text:

```python
def find_value(node, rule_name):
    queue = [node]
    while queue:
        n, queue = queue[0], queue[1:]
        if n.name == rule_name:
            return n.value
        queue.extend(n.children)
    return None

find_value(node, "opaque-tag")     # '"moof"'
```

For anything more involved than a single lookup, abnf provides `NodeVisitor`, which
dispatches a `visit_<rule_name>` method per rule as it walks the tree — see
{doc}`../how-to/extract-values-with-visitors` when you get there.

## 5. Validate input

`parse` stops at the longest match and doesn't care about leftover input. When you
want to confirm a string matches a rule *completely*, use `parse_all`, which raises
`ParseError` if anything is left over:

```python
from abnf import ParseError

rfc7232.Rule("ETag").parse_all('W/"moof"')     # returns the node, no error

try:
    rfc7232.Rule("ETag").parse_all('W/"moof" trailing junk')
except ParseError as exc:
    print("rejected:", exc)
```

That's the whole validation story: `parse_all` succeeds or it raises.

## 6. Write a tiny grammar

Finally, let's define a grammar instead of using a bundled one. A `Rule` subclass is
a grammar; `Rule.create` compiles one rule of ABNF into a parser. The core rules
(`ALPHA`, `DIGIT`, `SP`, …) are always available:

```python
from abnf import Rule

greeting = Rule.create('greeting = "hello" SP 1*ALPHA')

node = greeting.parse_all("hello world")
print(node.value)      # 'hello world'
```

Read that ABNF as: the literal `"hello"`, a space (`SP`), then one or more letters
(`1*ALPHA`). Try `greeting.parse_all("hello 123")` and watch it raise `ParseError`
— `123` isn't `1*ALPHA`.

## Where to go next

You've now installed abnf, parsed with a bundled grammar, read a parse tree,
extracted a value, validated input, and written your own rule. From here:

- **{doc}`../how-to/index`** — task recipes: visitors, loading grammars from files,
  building multi-rule grammar modules.
- **{doc}`../reference/index`** — the API, the core rules, and every bundled grammar.
- **{doc}`../explanation/index`** — how the combinator engine and the two backends
  actually work.
