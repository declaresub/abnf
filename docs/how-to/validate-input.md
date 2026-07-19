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
`GrammarError` (a different exception) means the grammar itself is unusable at that
point — an undefined rule or a prose-value — not that the input was invalid.
```
