# Validate input against a grammar

To check that a whole string conforms to a rule, use `parse_all`: it parses from the
start and raises `ParseError` unless the entire input is consumed.

```python
from abnf.grammars import rfc5322
from abnf import ParseError

def is_valid_email(src: str) -> bool:
    try:
        rfc5322.Rule("address").parse_all(src)
        return True
    except ParseError:
        return False

is_valid_email("test@example.com")          # True
is_valid_email("not an address")            # False
```

## `parse` vs. `parse_all`

- `parse(source, start)` returns `(node, offset)` and stops at the longest match it
  finds — it does **not** require consuming the whole string. Use it when the rule is
  a prefix of a larger input, and inspect the returned `offset`.
- `parse_all(source)` returns the `node` and raises `ParseError` if any input is left
  over. Use it for validation, when the entire string must match.

```python
node, offset = rfc5322.Rule("address").parse("test@example.com and more", 0)
# offset points just past the address; parse_all would have raised here
```

```{note}
A `ParseError` carries the parser and offset at which parsing failed. A
`GrammarError` (a different exception) means the grammar itself is unusable at
that point — an undefined rule — not that the input was invalid.
```

```{warning}
A **prose value** raises `ParseError`, not `GrammarError`. RFC grammars are full
of prose (`<any CHAR except CTLs>`), and `abnf` cannot implement English: a rule
containing one always fails, and it fails the same way a mismatched input does.

That is worth knowing because the failure need not surface as a rejection. If
the rule sits in an alternation, or is optional, some other alternative absorbs
the input and the parse *succeeds* with the prose rule missing from the tree:

```python
# RFC 9051 before issue #245: `resp-text-code` ended in a prose value, so
# `resp-text` fell through to `[text]`, which admits almost anything.
node = rfc9051.Rule("resp-text").parse_all("[MYCODE some text] hello")
[child.name for child in node.children]     # ['text'] -- no resp-text-code
```

Replace prose with the character set it describes. All the bundled grammars do,
and a test asserts none of them reaches a prose value.
```
