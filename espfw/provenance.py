"""Provenance stamped onto every output.

The point of this block is staleness detection: when the canonicalizer changes,
every signature and every prior analysis result computed under the old rules
must be identifiable as stale rather than silently comparable.
"""

from __future__ import annotations

from espfw import __version__
from espfw.schema import BaseModel, Field


class Provenance(BaseModel):
    """Identifies the exact code and data that produced a result."""

    tool_version: str = Field(default=__version__)
    canonicalizer_version: int = Field(
        description="espfw.canon.CANON_VERSION at the time of computation. "
        "Signatures with differing values are not comparable."
    )
    objdump_version: str | None = Field(
        default=None,
        description="Full `objdump --version` first line of the Xtensa binutils "
        "used for disassembly.",
    )
    corpus_revision: str | None = Field(
        default=None, description="Content revision of the signature store, if consulted."
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Anything that qualifies how the result was produced, e.g. "
        "that an ELF input's segments were reconstructed from its sections.",
    )


def current(objdump_version: str | None = None, corpus_revision: str | None = None) -> Provenance:
    """Build a provenance block for a result computed right now."""
    from espfw.canon import CANON_VERSION

    return Provenance(
        canonicalizer_version=CANON_VERSION,
        objdump_version=objdump_version,
        corpus_revision=corpus_revision,
    )
