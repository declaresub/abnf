"""Rust-backed parser engine for the ``abnf`` package.

Install via ``pip install abnf[rust]``.  When importable, the combinator
primitives in :mod:`abnf.parser` are routed through the compiled extension
exposed by this package.

The ``BACKEND_READY`` flag is consulted by ``abnf.parser`` to decide
whether the Rust backend is complete enough to use.  It will flip to
``True`` once the PyO3 bindings expose the full combinator surface; until
then ``abnf.parser`` falls back to its pure-Python implementation even
when this package is installed.
"""

BACKEND_READY = False
