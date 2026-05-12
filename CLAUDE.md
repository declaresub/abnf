# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`abnf` is a pure-Python parser generator for ABNF (Augmented Backus-Naur Form) grammars as defined in RFC 5234 and RFC 7405. It includes 30+ pre-built grammar modules for common RFCs (HTTP headers, email, URLs, etc.).

## Commands

**Testing:**
```bash
pytest --cov-report term-missing --cov=abnf          # All tests with coverage
pytest --cov-report term-missing --cov=abnf --ignore=tests/fuzz  # Skip fuzz tests
pytest tests/test_parser.py                           # Single test file
tox                                                   # Matrix across Python 3.10-3.14
```

**Linting & Formatting:**
```bash
ruff check src/abnf    # Lint
black src/abnf         # Format
pyright                # Type check
```

**Pre-commit hooks** run ruff, pyright, and check-manifest automatically.

## Architecture

### Core (`src/abnf/parser.py`)

The library implements **parser combinators** — primitive parsers are composed into complex grammars.

Key classes:
- `Rule` — Primary API class. Users subclass it to define grammars. Maintains a global per-class registry of named rules. Parses ABNF grammar strings into parser objects via `load()` or `from_file()`.
- `Node` / `LiteralNode` — Parse tree (AST) nodes, using `__slots__` for efficiency.
- `NodeVisitor` — Base visitor for traversing parse trees.
- `ParseCache` — LRU cache keyed on `(rule_name, source, start)` tuples; configurable via `Rule.max_cache_size`.
- `Alternation`, `Concatenation`, `Repetition`, `Option`, `Literal`, `Prose` — Internal parser combinator primitives (not part of public API).
- `ABNFGrammarRule` / `ABNFGrammarNodeVisitor` — Bootstrapped parser for ABNF grammar syntax itself; converts parsed ABNF text into `Rule`-based parser objects.

**Alternation behavior** is controlled by `Rule.first_match_alternation` (class attribute):
- `False` (default): longest match wins; ties broken by declaration order
- `True`: first match returned immediately

### Grammar Modules (`src/abnf/grammars/`)

Each module implements one RFC as a `Rule` subclass. The `@load_grammar_rules()` decorator in `misc.py` parses the embedded ABNF string at class definition time. Grammars can import rules from other RFC modules (e.g., `rfc7239` imports from `rfc7230`).

### Public API (`src/abnf/__init__.py`)

Exports: `Rule`, `Node`, `LiteralNode`, `NodeVisitor`, `ParseError`, `GrammarError`.

### Tests (`tests/`)

- `test_parser.py` — Core parser functionality
- `test_core_rules.py`, `test_misc.py` — Core rules and grammar utilities
- `tests/rfc*.py` — One test file per grammar module
- `tests/fuzz/` — Fuzz tests using abnfgen-generated inputs
- `tests/benchmarks/` — Performance benchmarks

## Adding a New Grammar Module

1. Create `src/abnf/grammars/rfc<NNNN>.py` subclassing `Rule`
2. Use `@load_grammar_rules()` or `@load_grammar_rulelist()` from `misc.py`
3. Create `tests/test_rfc<NNNN>.py` with corresponding tests
4. Export from `src/abnf/grammars/__init__.py` if needed

## Python Version Support

Targets Python 3.10–3.14. Use `X | Y` union syntax (not `typing.Union` or `typing.Optional`).
