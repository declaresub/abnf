"""Conditional typing imports are collected here, because doing the import below in 
parser.py appears to confuse pylance, causing it to flag objects as not conforming to
Parser protocol.  Adding Parser as a superclass of Rule leads to more odd type errors.
The code branches on version instead of using try-except so that mypy is happy.
"""


from typing import Protocol, runtime_checkable

__all__ = ["Protocol", "runtime_checkable"]  # pragma: no cover
