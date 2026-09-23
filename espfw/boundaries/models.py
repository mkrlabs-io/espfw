"""Schemas for recovered function boundaries."""

from __future__ import annotations

from enum import StrEnum

from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field, computed_field


class BoundaryConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FunctionBoundary(BaseModel):
    """One recovered function.

    On the target side these are *recovered*, not ground truth. A missed or
    misplaced boundary shows up downstream as an SDK function that "isn't
    there" — hence the explicit confidence and the reasons behind it.
    """

    entry: int = Field(description="Virtual address of the function entry point.")
    file_offset: int | None = Field(
        default=None, description="Offset in the input file, when the entry is in a segment."
    )
    size: int = Field(
        description="The extent, `span_end - entry` — the same thing a symbol's "
        "st_size states, so that the recovered side and the symbol-derived "
        "corpus side mean the same thing by 'how big is this function'."
    )
    ranges: list[tuple[int, int]] = Field(
        default_factory=list,
        description="Half-open [start, end) virtual address ranges that control "
        "flow actually reached. A function split around an interleaved literal "
        "pool, or around a switch table's unreachable arms, has more than one, "
        "and they can sum to less than `size` — that gap is what "
        "`confidence_reasons` reports as unverified extent.",
    )
    span_end: int = Field(
        default=0,
        description="End of the contiguous span [entry, span_end). This is the "
        "extent a symbol's st_size describes, so canonicalizing over the span "
        "rather than over the ranges makes recovered boundaries directly "
        "comparable with symbol-derived corpus boundaries.",
    )
    name: str | None = Field(
        default=None,
        description="Symbol name when the input had one. Always None for a "
        "stripped firmware image, which is the case this tool exists for — a "
        "recovered function has an address, not an identity, until `symbols` "
        "gives it one.",
    )
    region: str | None = None
    is_thunk: bool = False
    origins: list[str] = Field(
        default_factory=list,
        description="How this entry point was found: `image_entry`, "
        "`direct_call`, `prologue_scan`, `pointer`. A function reached "
        "only by inference is worth reading differently from one the call graph "
        "proves, so the evidence is carried rather than collapsed into the "
        "confidence grade.",
    )
    basic_blocks: int = 0
    edges: int = 0
    indirect_calls: int = Field(
        default=0,
        description="callx/jx sites: unresolved call-graph edges, recorded rather "
        "than dropped.",
    )
    callees: list[int] = Field(default_factory=list)
    confidence: BoundaryConfidence = BoundaryConfidence.MEDIUM
    confidence_reasons: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def range_count(self) -> int:
        """Ranges this function is split into. More than one means an
        interleaved literal pool or alignment padding.

        Declared because human output omits `ranges` itself; an absent list must
        not read as a missing function body.
        """
        return len(self.ranges)

    @computed_field
    @property
    def callee_count(self) -> int:
        """Resolved outgoing call edges. `indirect_calls` counts the rest."""
        return len(self.callees)


class BoundaryStats(BaseModel):
    total: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    named: int = 0
    thunks: int = 0
    bytes_in_functions: int = 0
    bytes_reached: int = Field(
        default=0,
        description="Bytes control flow actually decoded, which is at most "
        "`bytes_in_functions`. The difference is extent claimed on the strength "
        "of where the next function begins rather than on instructions read — "
        "worth seeing separately, because it is the part a modified-function "
        "verdict should not lean on.",
    )
    bytes_executable: int = 0
    coverage_ratio: float = Field(
        default=0.0,
        description="Executable bytes claimed by some function. Low coverage means "
        "boundary recovery missed code, not that the code isn't there.",
    )
    windowed_prologues: int = 0
    call0_prologues: int = 0


class FunctionSet(BaseModel):
    path: str
    chip: str
    recovery_version: str = Field(
        description="Version of the boundary-recovery algorithm that produced "
        "this set. Part of the memoization key."
    )
    functions: list[FunctionBoundary] = Field(default_factory=list)
    stats: BoundaryStats = Field(default_factory=BoundaryStats)
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None
