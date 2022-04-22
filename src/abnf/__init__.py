"""Parser generator for ABNF grammars."""

try:
    from importlib.metadata import metadata, PackageNotFoundError # type: ignore
except ImportError: # pragma: no cover
    from importlib_metadata import metadata, PackageNotFoundError # type: ignore

from .parser import Rule, Node, LiteralNode, NodeVisitor, ParseError, GrammarError # type: ignore

try:
    __version__ = metadata(__name__)['version']
except PackageNotFoundError: # pragma: no cover
    # package is not installed
    __version__ = ''
