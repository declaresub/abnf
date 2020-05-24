"""Parser generator for ABNF grammars."""

try:
    from importlib.metadata import metadata, PackageNotFoundError
except ImportError:
    from importlib_metadata import metadata, PackageNotFoundError

from .parser import Rule, Node, LiteralNode, NodeVisitor, ParseError, GrammarError

try:
    __version__ = metadata(__name__)['version']
except PackageNotFoundError:
    # package is not installed
    __version__ = ''
