"""Structured disassembly types.

Everything downstream — canonicalizer, matcher, diff — consumes these, never
raw objdump text and never a second disassembler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class InsnClass(StrEnum):
    """Control-flow role, which is what canonicalization and CFG building need."""

    NORMAL = "normal"
    CALL = "call"
    CALL_INDIRECT = "call_indirect"
    JUMP = "jump"
    JUMP_INDIRECT = "jump_indirect"
    BRANCH = "branch"
    RETURN = "return"
    LOOP = "loop"
    ENTRY = "entry"
    LITERAL_LOAD = "literal_load"
    DATA = "data"
    """objdump emitted `.byte` — it could not decode here. Usually a literal
    pool or padding rather than a decoder failure."""


@dataclass(slots=True)
class Instruction:
    addr: int
    size: int
    raw: bytes
    """Instruction bytes in memory order."""
    mnemonic: str
    operands: list[str] = field(default_factory=list)
    cls: InsnClass = InsnClass.NORMAL
    target: int | None = None
    """Resolved address for calls, jumps, branches and l32r. None when the
    target is register-indirect (callx/jx) — recorded as an unresolved edge
    rather than dropped."""
    literal_value: int | None = None
    """For l32r: the 32-bit word actually sitting in the literal pool, when the
    pool is inside a disassembled segment."""
    target_symbol: str | None = None
    """Symbol name objdump attached to the target, when disassembling something
    that still has a symbol table (i.e. corpus object files, never the target)."""

    @property
    def is_terminator(self) -> bool:
        return self.cls in (
            InsnClass.RETURN,
            InsnClass.JUMP,
            InsnClass.JUMP_INDIRECT,
        )

    def text(self) -> str:
        ops = ", ".join(self.operands)
        return f"{self.mnemonic} {ops}".strip()


@dataclass(slots=True)
class DisassembledSegment:
    """One loaded segment, decoded end to end."""

    load_addr: int
    length: int
    region: str | None
    instructions: list[Instruction]
    data: bytes = b""
    """Segment bytes, retained so l32r literals and data references resolve."""

    def index(self) -> dict[int, Instruction]:
        return {i.addr: i for i in self.instructions}

    def contains(self, addr: int) -> bool:
        return self.load_addr <= addr < self.load_addr + self.length

    def word_at(self, addr: int) -> int | None:
        """Read a little-endian 32-bit word at a virtual address."""
        off = addr - self.load_addr
        if off < 0 or off + 4 > len(self.data):
            return None
        return int.from_bytes(self.data[off : off + 4], "little")
