"""Function boundary recovery.

A stripped image has no symbol table, so "the firmware's functions" have to be
recovered before any later stage can talk about them. This is imperfect, and
its errors propagate into every downstream match rate — which is why boundaries
carry explicit confidence rather than being treated as ground truth.
"""

from espfw.boundaries.models import (
    BoundaryConfidence,
    BoundaryStats,
    FunctionBoundary,
    FunctionSet,
)
from espfw.boundaries.run import recover_functions

__all__ = [
    "BoundaryConfidence",
    "BoundaryStats",
    "FunctionBoundary",
    "FunctionSet",
    "recover_functions",
]
