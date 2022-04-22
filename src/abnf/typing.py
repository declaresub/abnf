"""Conditional typing imports are collected here, because doing the import below in 
parser.py appears to confuse pylance, causing it to flag objects as not conforming to
Parser protocol.  Adding Parser as a superclass of Rule leads to more odd type errors.
The code branches on version instead of using try-except so that mypy is happy.
"""

import sys

if sys.version_info >= (3, 8):
    from typing import Protocol # pragma: no cover
else:
    from typing_extensions import Protocol # pragma: no cover

__all__ = ["Protocol"]