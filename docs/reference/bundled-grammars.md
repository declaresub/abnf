# Bundled grammars

`abnf.grammars` contains a `Rule` subclass for each of the RFCs below. Import the
module and use its `Rule` to parse:

```python
from abnf.grammars import rfc5322

rfc5322.Rule("address").parse_all("test@example.com")
```

Some modules import rules by reference from others (for example, several HTTP
extensions reuse `token` and `OWS` from RFC 7230); this composition happens
automatically at import time. See {doc}`../how-to/write-your-own-grammar-module`
for how it is wired.

## HTTP core

| Module | RFC | Subject |
|---|---|---|
| `rfc2616` | 2616 | HTTP/1.1 (obsolete; a few rules are reused by later RFCs) |
| `rfc7230` | 7230 | HTTP/1.1 message syntax and routing (obsolete → 9110/9112) |
| `rfc7231` | 7231 | HTTP/1.1 semantics and content (obsolete → 9110) |
| `rfc7232` | 7232 | HTTP/1.1 conditional requests (obsolete → 9110) |
| `rfc7233` | 7233 | HTTP/1.1 range requests (obsolete → 9110) |
| `rfc7234` | 7234 | HTTP/1.1 caching (obsolete → 9111) |
| `rfc7235` | 7235 | HTTP/1.1 authentication (obsolete → 9110) |
| `rfc9110` | 9110 | HTTP semantics |
| `rfc9111` | 9111 | HTTP caching |

## HTTP extension headers

| Module | RFC | Subject |
|---|---|---|
| `rfc6265` | 6265 | HTTP state management (cookies) |
| `rfc6266` | 6266 | `Content-Disposition` header field |
| `rfc6797` | 6797 | HTTP Strict Transport Security (`Strict-Transport-Security`) |
| `rfc7239` | 7239 | `Forwarded` HTTP extension |
| `rfc7240` | 7240 | `Prefer` header field |
| `rfc7838` | 7838 | HTTP alternative services (`Alt-Svc`) |
| `rfc8288` | 8288 | Web linking (`Link` header) |
| `rfc9651` | 9651 | Structured field values for HTTP (obsoletes 8941) |

## Email

| Module | RFC | Subject |
|---|---|---|
| `rfc5322` | 5322 | Internet Message Format (email addresses, headers) |
| `rfc7489` | 7489 | DMARC |

## URIs, IRIs and encoding

| Module | RFC | Subject |
|---|---|---|
| `rfc3986` | 3986 | URI generic syntax |
| `rfc3987` | 3987 | Internationalized Resource Identifiers (IRIs) |
| `rfc3629` | 3629 | UTF-8 |
| `rfc5987` | 5987 | encoding for HTTP header parameters (obsolete → 8187) |
| `rfc8187` | 8187 | character encoding and language for HTTP header parameters |

## Language tags

| Module | RFC | Subject |
|---|---|---|
| `rfc4647` | 4647 | matching of language tags |
| `rfc5646` | 5646 | tags for identifying languages (BCP 47) |

## Dates, ABNF itself, and more

| Module | RFC | Subject |
|---|---|---|
| `rfc3339` | 3339 | date and time on the internet (timestamps) |
| `rfc5234` | 5234 | ABNF itself, plus the core rules (see `ABNFGrammarRule`) |
| `rfc7405` | 7405 | case-sensitive string support in ABNF |
| `rfc9051` | 9051 | IMAP4rev2 |
| `rfc9116` | 9116 | `security.txt` file format |

```{tip}
The module source is itself the best worked example of writing a grammar —
`abnf.grammars.rfc7230` in particular shows importing rules from another
`Rule` subclass.
```
