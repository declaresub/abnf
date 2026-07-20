"""Parser generator for ABNF grammars."""

from importlib.metadata import PackageNotFoundError, metadata  # pragma: no cover

from abnf.parser import (
    GrammarError,
    GrammarWarning,
    LiteralNode,
    Node,
    NodeVisitor,
    ParseError,
    Rule,
)

__all__ = [
    "GrammarError",
    "GrammarWarning",
    "LiteralNode",
    "Node",
    "NodeVisitor",
    "ParseError",
    "Rule",
    "__version__",
]

try:
    __version__ = metadata(__name__)["version"]
except PackageNotFoundError:  # pragma: no cover
    # package is not installed
    __version__ = ""
