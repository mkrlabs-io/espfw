"""Shared schema vocabulary.

Anything the tool infers rather than reads — today, the chip variant — comes
back as a ranked list of `Candidate`s with the evidence that drove the ranking,
because the evidence is how a wrong answer gets debugged.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Generic, TypeVar

from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field

T = TypeVar("T")


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Evidence(BaseModel):
    """One reason a candidate scored the way it did."""

    kind: str = Field(description="e.g. 'app_descriptor', 'marker_function', 'callgraph'")
    detail: str
    weight: float = 1.0


class Candidate(BaseModel, Generic[T]):
    """A ranked hypothesis with its supporting evidence."""

    value: T
    score: float = Field(description="Higher is better; comparable only within one ranking.")
    confidence: Confidence
    source: str = Field(description="Which mechanism produced this candidate.")
    evidence: list[Evidence] = Field(default_factory=list)


class Envelope(BaseModel):
    """Top-level shape of every --json output."""

    command: str
    provenance: Provenance
    warnings: list[str] = Field(default_factory=list)
    result: Any = None
