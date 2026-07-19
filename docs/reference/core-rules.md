# Core rules

Every `Rule` subclass is initialized with the RFC 5234 **core rules**, so they are
available by name in any grammar without being redefined:

```python
from abnf import Rule

Rule("ALPHA")   # already defined in every Rule subclass
```

| Rule | ABNF definition | Matches |
|---|---|---|
| `ALPHA` | `%x41-5A / %x61-7A` | `A`–`Z`, `a`–`z` |
| `BIT` | `"0" / "1"` | a binary digit |
| `CHAR` | `%x01-7F` | any 7-bit US-ASCII character except NUL |
| `CR` | `%x0D` | carriage return |
| `CRLF` | `CR LF` | Internet standard newline |
| `CTL` | `%x00-1F / %x7F` | control characters |
| `DIGIT` | `%x30-39` | `0`–`9` |
| `DQUOTE` | `%x22` | the double-quote `"` |
| `HEXDIG` | `DIGIT / "A" / "B" / "C" / "D" / "E" / "F"` | a hexadecimal digit |
| `HTAB` | `%x09` | horizontal tab |
| `LF` | `%x0A` | line feed |
| `LWSP` | `*(WSP / CRLF WSP)` | linear white space (see the RFC 5234 caveat) |
| `OCTET` | `%x00-FF` | any 8-bit byte |
| `SP` | `%x20` | a space |
| `VCHAR` | `%x21-7E` | any visible (printing) character |
| `WSP` | `SP / HTAB` | a space or horizontal tab |

```{note}
`HEXDIG` matches the hexadecimal letters case-insensitively, per the ABNF
convention that literal strings are case-insensitive unless declared otherwise
(see {doc}`../explanation/architecture` and RFC 7405).
```
