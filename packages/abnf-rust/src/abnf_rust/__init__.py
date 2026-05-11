"""Rust-backed parser engine for the ``abnf`` package.

Install via ``pip install abnf[rust]``.  When importable, the combinator
primitives in :mod:`abnf.parser` are routed through the compiled
extension exposed by this package.
"""

from abnf_rust._ext import (  # type: ignore[import-not-found]
    Alternation,
    Concatenation,
    Literal,
    LiteralNode,
    Match,
    Node,
    Option,
    Prose,
    Repeat,
    Repetition,
    bootstrap,
)

BACKEND_READY = True

__all__ = [
    "BACKEND_READY",
    "Alternation",
    "Concatenation",
    "Literal",
    "LiteralNode",
    "Match",
    "Node",
    "Option",
    "Prose",
    "Repeat",
    "Repetition",
    "bootstrap",
]
