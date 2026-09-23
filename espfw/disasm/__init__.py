"""The single disassembly path: Xtensa GNU binutils objdump.

Nothing else in espfw may decode Xtensa instructions. General-purpose engines
have historically had weak or absent Xtensa support and can mis-decode
silently, and a decoder that is subtly wrong is worse than one that errors.
"""

from espfw.disasm.objdump import (
    disassemble_binary,
    disassemble_object,
    disassemble_ranges,
    resolve_literals,
)
from espfw.disasm.toolchain import (
    describe_toolchains,
    find_objdump,
    objdump_version,
    toolchain_id,
)
from espfw.disasm.types import DisassembledSegment, InsnClass, Instruction

__all__ = [
    "DisassembledSegment",
    "InsnClass",
    "Instruction",
    "describe_toolchains",
    "disassemble_binary",
    "disassemble_object",
    "disassemble_ranges",
    "find_objdump",
    "objdump_version",
    "resolve_literals",
    "toolchain_id",
]
