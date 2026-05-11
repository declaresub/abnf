"""Parser core; dispatches between the pure-Python implementation and the
optional Rust backend.

The Rust backend is provided by the optional ``abnf-rust`` distribution,
installed via ``pip install abnf[rust]``.  When ``abnf_rust`` is importable
its compiled combinators replace the pure-Python versions in this module.

Set the environment variable ``ABNF_NO_RUST`` to force the pure-Python
backend even when ``abnf_rust`` is installed (useful for debugging and
benchmarking).

The attribute ``_BACKEND`` on this module is either ``"python"`` or
``"rust"`` and reflects the active backend.
"""

from __future__ import annotations

import os
import typing

# The pure-Python implementation is always loaded.  It supplies the
# canonical Rule / NodeVisitor / exception types (which never have
# Rust-backed equivalents) and is the fallback backend.
from abnf import _parser_python as _py
from abnf._parser_python import (
    ABNFGrammarRule,
    GrammarError,
    Matches,
    MatchSet,
    Nodes,
    NodeVisitor,
    ParseCacheKey,
    ParseCacheValue,
    ParseError,
    Parser,
    Rule,
    Source,
)

# ``_backend`` is a module object: either ``abnf._parser_python`` or
# ``abnf_rust``.  Typed as ``Any`` because the Rust extension exposes
# pyclasses whose Python signatures pyright cannot statically resolve.
_backend: typing.Any

if os.environ.get("ABNF_NO_RUST"):
    _backend = _py
    _BACKEND = "python"
else:
    try:
        import abnf_rust as _abnf_rust  # type: ignore[import-not-found]

        _backend = _abnf_rust
        _BACKEND = "rust"
    except ImportError:
        _backend = _py
        _BACKEND = "python"

# Combinator and helper primitives.  These are rebound to whichever
# backend is active; existing imports (``from abnf.parser import
# Alternation`` etc.) continue to work transparently.
Alternation = _backend.Alternation
Concatenation = _backend.Concatenation
Repetition = _backend.Repetition
Option = _backend.Option
Literal = _backend.Literal
Prose = _backend.Prose
Repeat = _backend.Repeat
Match = _backend.Match
Node = _backend.Node
LiteralNode = _backend.LiteralNode
ParseCache = _backend.ParseCache
ABNFGrammarNodeVisitor = _backend.ABNFGrammarNodeVisitor
CharValNodeVisitor = _backend.CharValNodeVisitor
NumValVisitor = _backend.NumValVisitor
sorted_by_longest_match = _backend.sorted_by_longest_match
next_longest = _backend.next_longest

if _BACKEND == "rust":
    # Replace the pure-Python combinator trees registered into
    # ``ABNFGrammarRule._obj_map`` at ``_parser_python`` import time with
    # Rust-backed equivalents.  See ``abnf_rust.bootstrap`` for details.
    _backend.bootstrap(ABNFGrammarRule)


__all__ = [
    "ABNFGrammarNodeVisitor",
    "ABNFGrammarRule",
    "Alternation",
    "CharValNodeVisitor",
    "Concatenation",
    "GrammarError",
    "Literal",
    "LiteralNode",
    "Match",
    "MatchSet",
    "Matches",
    "Node",
    "NodeVisitor",
    "Nodes",
    "NumValVisitor",
    "Option",
    "ParseCache",
    "ParseCacheKey",
    "ParseCacheValue",
    "ParseError",
    "Parser",
    "Prose",
    "Repeat",
    "Repetition",
    "Rule",
    "Source",
    "next_longest",
    "sorted_by_longest_match",
]
