# ABNF

[![PyPI](https://img.shields.io/pypi/v/abnf)](https://pypi.org/project/abnf/)
![abnf-tox](https://github.com/declaresub/abnf/workflows/abnf-tox/badge.svg)
[![CodeQL](https://github.com/declaresub/abnf/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/declaresub/abnf/actions/workflows/codeql-analysis.yml)

ABNF generates parsers from ABNF grammars as described in
[RFC 5234](https://tools.ietf.org/html/rfc5234) and
[RFC 7405](https://tools.ietf.org/html/rfc7405). Its main purpose is parsing data
specified in RFCs — HTTP headers, email addresses, URIs, and the like — but it
handles any ABNF grammar. It ships with 30+ ready-to-use grammar modules for common
RFCs and has been in production use since it was first written for parsing HTTP
headers in a web framework.

## Installation

```console
pip install abnf
pip install 'abnf[rust]'   # optional Rust backend, for substantially faster parsing
```

ABNF is tested with Python 3.10–3.14.

## Quick start

```python
from abnf.grammars import rfc7232

# parse an ETag header value
node, offset = rfc7232.Rule("ETag").parse('W/"moof"', 0)
print(node.value)          # 'W/"moof"'

# validate a whole string against a rule (raises ParseError otherwise)
from abnf.grammars import rfc5322
rfc5322.Rule("address").parse_all("test@example.com")

# compile your own rule; the RFC 5234 core rules are always available
from abnf import Rule
greeting = Rule.create('greeting = "hello" SP 1*ALPHA')
greeting.parse_all("hello world")
```

## Documentation

Full documentation follows the [Diátaxis](https://diataxis.fr/) framework:

- **Tutorial** — *Parse your first header*, a ten-minute end-to-end walkthrough.
- **How-to guides** — validate input, extract values with visitors, load a grammar
  from a file, write your own grammar module, use the Rust backend.
- **Reference** — the public API, the built-in core rules, the bundled grammars, and
  configuration knobs.
- **Explanation** — the combinator architecture, the two backends, alternation
  semantics, and how backtracking is kept in check.

To build the docs locally:

```console
pip install -e '.[docs]'
sphinx-build -W docs docs/_build/html
```

## Contributing

Set up a development environment with the `dev` extra:

```console
pip install -e '.[dev]'          # or: uv sync --extra dev
```

Run the test suite (skip the slower fuzz tests with `--ignore=tests/fuzz`):

```console
pytest --cov-report term-missing --cov=abnf
```

Pre-commit hooks run ruff, pyright, check-manifest, and tox. Install them once with
`pre-commit install`. See the *Explanation* and *How-to* docs for working with the
Rust backend.

## Third-party packages

- [abnf-to-regexp](https://pypi.org/project/abnf-to-regexp/) — converts ABNF to a
  regular expression.
