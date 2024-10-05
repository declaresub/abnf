"""Parser generator for ABNF grammars."""


from importlib.metadata import PackageNotFoundError, metadata  # pragma: no cover

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
