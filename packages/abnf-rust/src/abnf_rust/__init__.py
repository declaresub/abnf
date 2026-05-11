"""Rust-backed parser engine for the ``abnf`` package.

Install via ``pip install abnf[rust]``.  When importable, the combinator
primitives in :mod:`abnf.parser` are routed through the compiled
extension exposed by this package.

The pure-Python implementation of ``abnf`` remains the canonical
reference; this package is purely an acceleration layer and falls
back transparently when the environment variable ``ABNF_NO_RUST`` is
set.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

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
    set_definition_hook,
)

#: Signals to :mod:`abnf.parser` that the compiled extension exposes
#: the full combinator surface and is safe to dispatch to.  An
#: in-development or partial build can ship with this set to ``False``
#: to keep the dispatch shim on the pure-Python fallback.
BACKEND_READY = True

try:
    __version__ = _pkg_version("abnf-rust")
except PackageNotFoundError:  # pragma: no cover
    __version__ = ""

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
    "__version__",
    "bootstrap",
    "set_definition_hook",
]
