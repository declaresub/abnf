# ABNF

[![PyPI](https://img.shields.io/pypi/v/abnf)](https://pypi.org/project/abnf/)
![abnf-tox](https://github.com/declaresub/abnf/workflows/abnf-tox/badge.svg)
[![CodeQL](https://github.com/declaresub/abnf/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/declaresub/abnf/actions/workflows/codeql-analysis.yml)
[![Docs](https://readthedocs.org/projects/abnf/badge/?version=latest)](https://abnf.readthedocs.io/en/latest/)

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

## Parsing bytes

`abnf` parses code points, so `parse` and `parse_all` take a `str`. To parse wire
data, decode it with latin-1 — that maps the 256 byte values onto `U+0000`–`U+00FF`
one to one, so a code point is exactly an octet and octet-oriented grammars behave
as their RFCs describe:

```python
rfc7230.Rule("request-line").parse_all(raw.decode("latin-1"))
```

See [What abnf parses](https://abnf.readthedocs.io/en/latest/explanation/what-abnf-parses.html)
for why the encoding is the caller's choice.

## Documentation

Full documentation is hosted at **[abnf.readthedocs.io](https://abnf.readthedocs.io/en/latest/)**
and follows the [Diátaxis](https://diataxis.fr/) framework:

- **Tutorial** — *Parse your first header*, a ten-minute end-to-end walkthrough.
- **How-to guides** — validate input, extract values with visitors, load a grammar
  from a file, write your own grammar module, exclude matches from a rule, use the
  Rust backend.
- **Reference** — the public API, the built-in core rules, the bundled grammars, and
  configuration knobs.
- **Explanation** — what abnf parses (code points, not bytes), the combinator
  architecture, the two backends, alternation semantics, and how backtracking is
  kept in check.

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

`tests/fuzz/` holds two committed corpora, replayed by every run. If you change a
grammar module, regenerate them:

```console
python tests/fuzz/gen_corpus.py rfc9051           # Hypothesis, walks the built parser
python tests/fuzz/gen_abnfgen_corpus.py rfc9051   # abnfgen, reads the grammar text
```

The second needs [abnfgen](http://www.quut.com/abnfgen/) on your PATH (or `ABNFGEN`
set to it); CI only replays what is committed. Reading the text rather than the
built parser is the point — it catches a grammar that did not become the parser it
describes, which a generator walking that parser cannot.

Pre-commit hooks run ruff, pyright, check-manifest, and tox. Install them once with
`pre-commit install`. See the *Explanation* and *How-to* docs for working with the
Rust backend.

## Third-party packages

- [abnf-to-regexp](https://pypi.org/project/abnf-to-regexp/) — converts ABNF to a
  regular expression.
