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

        if not getattr(_abnf_rust, "BACKEND_READY", False):
            # The companion package is installed but its compiled
            # extension does not yet expose the full combinator surface
            # (e.g. an in-development build).  Fall back silently.
            msg = "abnf_rust backend not ready"
            raise ImportError(msg)
        _backend = _abnf_rust
        _BACKEND = "rust"
    except ImportError:
        _backend = _py
        _BACKEND = "python"

# Backend-swappable primitives.  The Rust backend exposes its own
# pyclass equivalents of these; everything else (ParseCache, the
# visitors, the utility functions) is shared with the Python
# implementation regardless of which backend is active.
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

# Always-Python helpers.  The Rust backend re-uses these from the
# pure-Python module to avoid duplicating their (cheap) logic.
ParseCache = _py.ParseCache
ABNFGrammarNodeVisitor = _py.ABNFGrammarNodeVisitor
CharValNodeVisitor = _py.CharValNodeVisitor
NumValVisitor = _py.NumValVisitor
sorted_by_longest_match = _py.sorted_by_longest_match
next_longest = _py.next_longest

if _BACKEND == "rust":
    # Monkey-patch the pure-Python module's free name bindings so the
    # visitor methods defined there (which build combinator trees
    # while walking a parsed `rulelist`) construct Rust-backed
    # combinators instead of pure-Python ones.  Without this, a
    # `Rule.create("foo = bar")` call would still install a
    # pure-Python `Alternation` / `Concatenation` / ... tree as the
    # rule's definition, defeating the Rust speedup.
    _py.Alternation = Alternation
    _py.Concatenation = Concatenation
    _py.Repetition = Repetition
    _py.Option = Option
    _py.Literal = Literal
    _py.Prose = Prose
    _py.Repeat = Repeat
    _py.Node = Node
    _py.LiteralNode = LiteralNode
    _py.Match = Match
    # Wire the definition-sync hook so every `rule.definition = ...`
    # write mirrors into the Rust side's NamedRule registry.  Without
    # this, rule references in user grammars dispatch through Python's
    # `Rule.lparse` on every call, bottlenecking the Rust engine.
    Rule._set_definition_hook = staticmethod(_backend.set_definition_hook)
    # Replace the pure-Python combinator trees registered into
    # ABNFGrammarRule._obj_map at _parser_python import time with
    # Rust-backed equivalents.  See abnf_rust.bootstrap.
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
