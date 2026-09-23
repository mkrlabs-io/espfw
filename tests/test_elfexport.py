"""Loadable-ELF export tests.

The file this writes is the substrate an analysis is carried out on, so it has to
be correct without anything downstream compensating. These tests read it back
with espfw's own ELF reader, which parses the format independently of the writer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from espfw import elfreader
from espfw.elfwriter import write_program_elf

CODE = bytes.fromhex("364100" "1df0") * 8
DATA = bytes(range(64))
IRAM, DRAM = 0x40080000, 0x3FFB0000


def _elf(tmp_path: Path) -> Path:
    return write_program_elf(
        tmp_path / "out.elf",
        [
            (".dram0.data", DRAM, DATA, False),
            (".iram0.text", IRAM, CODE, True),
        ],
        entry=IRAM,
    )


def test_the_file_is_a_valid_elf32_xtensa_executable(tmp_path):
    elf = elfreader.load(_elf(tmp_path))
    assert elf.e_machine == 94, "EM_XTENSA — a wrong machine makes it unopenable"
    assert elf.e_entry == IRAM


def test_segments_keep_their_load_addresses(tmp_path):
    """The whole point: a raw .bin puts this code at file offset 0, where every
    absolute address in the image points outside the program."""
    elf = elfreader.load(_elf(tmp_path))
    by_name = {s.name: s for s in elf.sections}
    assert by_name[".iram0.text"].addr == IRAM
    assert by_name[".iram0.text"].data() == CODE
    assert by_name[".dram0.data"].addr == DRAM
    assert by_name[".dram0.data"].data() == DATA


def test_permissions_come_from_the_section_flags(tmp_path):
    """A disassembler reads executability off the section, and will not
    disassemble a block it believes is data."""
    elf = elfreader.load(_elf(tmp_path))
    by_name = {s.name: s for s in elf.sections}
    assert by_name[".iram0.text"].is_code
    assert not by_name[".dram0.data"].is_code


def test_no_symbols_are_written(tmp_path):
    """By design. Where functions begin and what they are called is a separate
    question, answered against this file rather than baked into it."""
    elf = elfreader.load(_elf(tmp_path))
    assert elf.symbols() == []
    assert ".symtab" not in {s.name for s in elf.sections}


def test_writing_an_elf_with_no_data_is_refused(tmp_path):
    with pytest.raises(ValueError):
        write_program_elf(tmp_path / "empty.elf", [], entry=0)


# --- end to end, against a real image ----------------------------------------

ARTIFACTS = Path.home() / ".cache/espfw/selftest/v5.4-default/app"
needs_image = pytest.mark.skipif(
    not (ARTIFACTS / "hello_world.bin").is_file(),
    reason="no self-built image; run a corpus build first",
)


@needs_image
def test_export_maps_a_real_image(tmp_path):
    """Needs no toolchain and no corpus — mapping is a `flash-info` fact."""
    from espfw.elfexport import build_analysis_elf

    result = build_analysis_elf(ARTIFACTS / "hello_world.bin", tmp_path / "hello.elf")
    names = [sec.name for sec in result.sections]
    assert ".iram0.text" in names
    assert ".flash.text" in names
    # Two IRAM segments is the normal shape, and section names have to stay
    # unique or the second one is unaddressable.
    assert len(names) == len(set(names))

    elf = elfreader.load(result.path)
    assert elf.e_entry == result.entry
    loaded = {s.name: s.addr for s in elf.sections if s.addr}
    for sec in result.sections:
        assert loaded[sec.name] == sec.vaddr


@needs_image
def test_the_exported_elf_agrees_with_the_image_it_came_from(tmp_path):
    """Byte-for-byte: an address read out of the ELF must be the same address
    the image had, or every mapping produced against it later is wrong."""
    from espfw.elfexport import build_analysis_elf
    from espfw.parse import parse_file

    image = ARTIFACTS / "hello_world.bin"
    result = build_analysis_elf(image, tmp_path / "hello.elf")

    parsed = parse_file(image)
    img = parsed.images[parsed.selected_image]
    data = image.read_bytes()
    elf = elfreader.load(result.path)
    by_addr = {s.addr: s for s in elf.sections if s.addr}

    for seg in img.segments:
        if not seg.length:
            continue
        section = by_addr[seg.load_addr]
        assert section.data() == data[seg.file_offset : seg.file_offset + seg.length]
        assert section.is_code == bool(seg.executable)
