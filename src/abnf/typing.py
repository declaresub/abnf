"""Conditional typing imports are collected here, because doing the import below in 
parser.py appears to confuse pylance, causing it to flag objects as not conforming to
Parser protocol.  Adding Parser as a superclass of Rule leads to more odd type errors.
The code branches on version instead of using try-except so that mypy is happy.
"""

import sys  # pragma: no cover

if sys.version_info >= (3, 8):  # pragma: no cover
    from typing import Protocol, runtime_checkable
else:
    from typing_extensions import Protocol, runtime_checkable  # pragma: no cover

__all__ = ["Protocol", "runtime_checkable"]  # pragma: no cover
