"""Parser generator for ABNF grammars."""

try:
    from importlib.metadata import PackageNotFoundError, metadata  # type: ignore
except ImportError:  # pragma: no cover
    from importlib_metadata import metadata, PackageNotFoundError  # type: ignore

from .parser import GrammarError, LiteralNode, Node, NodeVisitor, ParseError, Rule

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
