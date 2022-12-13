"""Parser generator for ABNF grammars."""

import sys

if sys.version_info >= (3, 8):
    from importlib.metadata import PackageNotFoundError, metadata  # pragma: no cover
else:
    from importlib_metadata import metadata, PackageNotFoundError  # pragma: no cover

from abnf.parser import GrammarError, LiteralNode, Node, NodeVisitor, ParseError, Rule

__all__ = [
    "Rule",
    "Node",
    "LiteralNode",
    "NodeVisitor",
    "ParseError",
    "GrammarError",
    "__version__",
]

try:
    __version__ = metadata(__name__)["version"]
except PackageNotFoundError:  # pragma: no cover
    # package is not installed
    __version__ = ""
