"""Disassembly backend tests.

Skipped when no Xtensa toolchain is installed — the point is that we do
not fall back to another disassembler, so with no toolchain there is nothing to
test rather than something to approximate.
"""

from __future__ import annotations

import pytest

from espfw.disasm import disassemble_binary, disassemble_ranges
from espfw.disasm.objdump import classify
from espfw.disasm.types import InsnClass
from espfw.elfreader import Elf32, ar_members
from espfw.elfwriter import write_elf, write_sectioned_elf
from espfw.errors import ToolchainError

try:
    from espfw.disasm.toolchain import find_objdump

    find_objdump("esp32")
    HAVE_TOOLCHAIN = True
except ToolchainError:
    HAVE_TOOLCHAIN = False

needs_toolchain = pytest.mark.skipif(
    not HAVE_TOOLCHAIN, reason="no Xtensa binutils installed"
)

# entry a1, 48 ; nop ; retw.n  — a minimal windowed function.
WINDOWED_FN = bytes.fromhex("36410020f0" "20f0" "1df0")


def test_instruction_classification():
    assert classify("call8") is InsnClass.CALL
    assert classify("callx8") is InsnClass.CALL_INDIRECT
    assert classify("retw.n") is InsnClass.RETURN
    assert classify("l32r") is InsnClass.LITERAL_LOAD
    assert classify("entry") is InsnClass.ENTRY
    assert classify("beqz") is InsnClass.BRANCH
    assert classify("bbci") is InsnClass.BRANCH
    assert classify("j") is InsnClass.JUMP
    assert classify("jx") is InsnClass.JUMP_INDIRECT
    assert classify(".byte") is InsnClass.DATA
    # `break` starts with b but is not a branch.
    assert classify("break") is not InsnClass.BRANCH
    assert classify("add") is InsnClass.NORMAL


@needs_toolchain
def test_raw_segment_disassembly_tiles_every_byte():
    """Instructions must exactly cover the input, or downstream offsets shift."""
    data = bytes.fromhex("36412000") * 32
    seg = disassemble_binary("esp32", data, 0x400D0000)
    assert sum(i.size for i in seg.instructions) == len(data)
    assert seg.instructions[0].addr == 0x400D0000


@needs_toolchain
def test_disassembly_uses_the_supplied_load_address():
    data = bytes.fromhex("36412000") * 4
    a = disassemble_binary("esp32", data, 0x400D0000)
    b = disassemble_binary("esp32", data, 0x40080000)
    assert a.instructions[0].addr == 0x400D0000
    assert b.instructions[0].addr == 0x40080000


@needs_toolchain
def test_ranges_are_decoded_from_their_own_entry_points():
    """Each range becomes its own section so objdump restarts there; a shared
    linear sweep would desynchronize across literal pools."""
    out = disassemble_ranges(
        "esp32",
        [("a", 0x400D0000, WINDOWED_FN), ("b", 0x40080000, WINDOWED_FN)],
    )
    assert set(out) == {"a", "b"}
    assert out["a"][0].mnemonic == "entry"
    assert out["b"][0].mnemonic == "entry"
    assert out["a"][0].addr == 0x400D0000
    assert out["b"][0].addr == 0x40080000


@needs_toolchain
def test_empty_ranges_are_skipped_without_error():
    assert disassemble_ranges("esp32", [("a", 0x400D0000, b"")]) == {}


def test_unknown_chip_is_rejected():
    with pytest.raises(ToolchainError):
        find_objdump("nonexistent-chip")


def test_riscv_part_has_no_disassembler():
    with pytest.raises(ToolchainError, match="not an Xtensa part"):
        find_objdump("esp32c3")


def test_elf_writer_output_is_readable(tmp_path):
    p = write_elf(tmp_path / "o.elf", [(0x400D0000, b"\x01" * 64, True)], entry=0x400D0000)
    elf = Elf32(p.read_bytes())
    assert elf.e_machine == 94
    assert elf.e_entry == 0x400D0000


def test_sectioned_elf_writer_roundtrips(tmp_path):
    p = write_sectioned_elf(
        tmp_path / "s.elf",
        [(".espfw0", 0x400D0000, b"\xaa" * 8), (".espfw1", 0x40080000, b"\xbb" * 8)],
    )
    elf = Elf32(p.read_bytes())
    names = {s.name for s in elf.sections}
    assert {".espfw0", ".espfw1"} <= names
    sec = elf.section(".espfw1")
    assert sec.addr == 0x40080000
    assert sec.data() == b"\xbb" * 8


def test_ar_reader_handles_long_member_names():
    """GNU long-name tables are what real component archives use."""
    longname = "a_very_long_object_file_name_that_needs_the_table.c.obj"
    strtab = (longname + "/\n").encode()

    def header(name, size):
        return (
            name.ljust(16).encode()
            + b"0".ljust(12)
            + b"0".ljust(6) + b"0".ljust(6)
            + b"100644".ljust(8)
            + str(size).ljust(10).encode()
            + b"\x60\n"
        )

    body = b"!<arch>\n"
    body += header("//", len(strtab)) + strtab + (b"\n" if len(strtab) % 2 else b"")
    payload = b"CONTENT!"
    body += header("/0", len(payload)) + payload

    members = ar_members(body)
    assert members == [(longname, payload)]
