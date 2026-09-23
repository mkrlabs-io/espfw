"""Build a loadable ELF from a firmware image.

A raw `.bin` is not something a disassembler can open usefully: it has no memory
map, so the code loaded at `0x400d0020` lands at file offset 0 and every absolute
address in the image points outside the program. This gives the bytes their
addresses back, and stops there.

Deliberately no symbols. Where functions begin and what they are called is a
separate question, answered separately and against this file — the ELF is the
substrate an analysis is carried out on, not the place its conclusions are
stored. Keeping it that way means the file is cheap (no toolchain, no corpus, no
boundary recovery), stable (it does not change when the matcher improves), and
honest about what it is: the image, mapped.
"""

from __future__ import annotations

from pathlib import Path

from espfw.elfwriter import write_program_elf
from espfw.errors import EspfwError
from espfw.parse import parse_file
from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field, computed_field

# Conventional ESP-IDF section names per memory region, so an analyst opening the
# program sees blocks named the way the linker script names them rather than six
# anonymous spans.
_SECTION_NAMES = {
    "irom": ".flash.text",
    "drom": ".flash.rodata",
    "iram": ".iram0.text",
    "dram": ".dram0.data",
    "rtc_iram": ".rtc.text",
    "rtc_dram": ".rtc.data",
    "diram_iram": ".iram0.text",
    "diram_dram": ".dram0.data",
}


class MappedSection(BaseModel):
    """One segment as it was written into the ELF."""

    name: str
    vaddr: int
    size: int
    executable: bool
    file_offset: int = Field(
        description="Where these bytes start in the *source image*, not in the "
        "ELF. An address seen in the loaded program converts back to an offset "
        "in the firmware file as `file_offset + (addr - vaddr)`, which is what "
        "makes a finding reportable against the thing that was flashed."
    )

    @computed_field
    @property
    def vaddr_hex(self) -> str:
        return f"{self.vaddr:#010x}"


class ElfExport(BaseModel):
    """Where the image ended up and how it was mapped."""

    path: str
    image: str
    chip: str | None = None
    entry: int = 0
    sections: list[MappedSection] = Field(
        default_factory=list,
        description="The map itself: an address read out of the loaded program "
        "is only meaningful against it.",
    )
    bytes_written: int = 0
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None


def build_analysis_elf(
    image_path: str | Path,
    out_path: str | Path,
    slot: str | None = None,
) -> ElfExport:
    """Write the selected app image as an ELF at `out_path`."""
    parsed = parse_file(image_path, select_slot=slot)
    if parsed.selected_image is None:
        raise EspfwError("no application image was selected to export")

    img = parsed.images[parsed.selected_image]
    data = Path(parsed.path).read_bytes()

    segments: list[tuple[str, int, bytes, bool]] = []
    mapped: list[MappedSection] = []
    used: dict[str, int] = {}
    for seg in img.segments:
        if not seg.length:
            continue
        base = _SECTION_NAMES.get(seg.region or "", ".segment")
        # Two segments can share a region — an image commonly has two IRAM
        # segments — and section names have to stay unique to be addressable.
        count = used.get(base, 0)
        used[base] = count + 1
        name = base if count == 0 else f"{base}.{count}"
        blob = data[seg.file_offset : seg.file_offset + seg.length]
        segments.append((name, seg.load_addr, blob, bool(seg.executable)))
        mapped.append(
            MappedSection(
                name=name,
                vaddr=seg.load_addr,
                size=seg.length,
                executable=bool(seg.executable),
                file_offset=seg.file_offset,
            )
        )

    if not segments:
        raise EspfwError("the selected image has no segment data to export")

    out = Path(out_path)
    write_program_elf(out, segments, entry=img.header.entry_addr)

    from espfw import provenance

    return ElfExport(
        path=str(out),
        image=parsed.path,
        chip=parsed.chip,
        entry=img.header.entry_addr,
        sections=mapped,
        bytes_written=out.stat().st_size,
        warnings=list(parsed.warnings),
        provenance=provenance.current(),
    )
