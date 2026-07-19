"""Sphinx configuration for the abnf documentation.

Prose (tutorial / how-to / explanation) is authored in Markdown via MyST; the
API reference is generated from the package's docstrings with autodoc.
"""

import os
from importlib.metadata import version as _version

# Document the pure-Python backend: the classes autodoc renders (Rule, Node,
# NodeVisitor, the exceptions) are always the pure-Python ones regardless of
# backend, and forcing it keeps the build independent of whether the optional
# abnf_rust extension happens to be installed in the build environment.
os.environ.setdefault("ABNF_NO_RUST", "1")

project = "abnf"
author = "Charles Yeomans"
copyright = "Charles Yeomans"  # noqa: A001

# The full version, including alpha/beta/rc tags.
release = _version("abnf")
# The short X.Y version.
version = ".".join(release.split(".")[:2])

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "myst_parser",
    "sphinx_copybutton",
]

# MyST (Markdown) options.
myst_enable_extensions = [
    "colon_fence",  # ::: fenced directives, incl. admonitions
    "deflist",
    "smartquotes",
]
myst_heading_anchors = 3  # auto-generate anchors for h1..h3

source_suffix = {
    ".md": "markdown",
    ".rst": "restructuredtext",
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Autodoc ---------------------------------------------------------------

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_member_order = "bysource"
autodoc_typehints = "description"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- HTML output -----------------------------------------------------------

html_theme = "furo"
html_static_path = ["_static"]
html_title = f"abnf {version}"
