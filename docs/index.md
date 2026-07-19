# abnf

**abnf** generates parsers from [ABNF](https://tools.ietf.org/html/rfc5234) grammars
(RFC 5234 and RFC 7405). Its main purpose is parsing data specified in RFCs — HTTP
headers, email addresses, URIs, and the like — but it handles any ABNF grammar. It
ships with 30+ ready-to-use grammar modules for common RFCs and has been used in
production since it was first written for parsing HTTP headers in a web framework.

```python
from abnf.grammars import rfc7232

node, _ = rfc7232.Rule("ETag").parse('W/"moof"', 0)
```

## Installation

```console
pip install abnf
pip install 'abnf[rust]'   # optional Rust backend, for substantially faster parsing
```

See {doc}`how-to/use-the-rust-backend` for what the `[rust]` extra buys you.

## The documentation

This documentation follows the [Diátaxis](https://diataxis.fr/) framework — four
kinds of material, each answering a different need:

- **{doc}`Tutorial <tutorial/parse-your-first-header>`** — learning-oriented. Start
  here if you are new: build a working parser end to end.
- **{doc}`How-to guides <how-to/index>`** — task-oriented recipes for specific goals:
  validate input, walk a parse tree, load a grammar from a file, write your own
  grammar module, use the Rust backend.
- **{doc}`Reference <reference/index>`** — information-oriented. The public API, the
  built-in core rules, the bundled grammars, and configuration knobs.
- **{doc}`Explanation <explanation/index>`** — understanding-oriented discussion: the
  combinator architecture, the two backends, alternation semantics, and how
  backtracking is kept in check.

```{toctree}
:hidden:
:caption: Tutorial

tutorial/parse-your-first-header
```

```{toctree}
:hidden:
:caption: How-to guides

how-to/index
how-to/validate-input
how-to/extract-values-with-visitors
how-to/load-a-grammar-from-a-file
how-to/write-your-own-grammar-module
how-to/use-the-rust-backend
```

```{toctree}
:hidden:
:caption: Reference

reference/index
reference/api
reference/core-rules
reference/bundled-grammars
reference/configuration
```

```{toctree}
:hidden:
:caption: Explanation

explanation/index
explanation/architecture
explanation/backends
explanation/alternation-semantics
explanation/backtracking-and-caching
explanation/rust-backend-performance
```
