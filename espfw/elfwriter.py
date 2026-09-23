"""Synthesize an ELF32 Xtensa executable from loaded segments.

Boundary recovery wants every segment mapped at its true load address in one
program, so that cross-segment calls resolve and the recovered call graph is
whole. Handing Ghidra one flat binary per segment would lose exactly that.

This writer only ever emits what `flash-info` already knows — it invents no
symbols and no section semantics.
"""

from __future__ import annotations

import struct
from pathlib import Path

EM_XTENSA = 94
ET_EXEC = 2
PT_LOAD = 1
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

EHDR_SIZE = 52
PHDR_SIZE = 32
PAGE = 0x1000


def write_elf(
    path: str | Path,
    segments: list[tuple[int, bytes, bool]],
    entry: int = 0,
) -> Path:
    """Write an ET_EXEC Xtensa ELF mapping `segments` as (load_addr, data, executable)."""
    out = Path(path)
    segs = [s for s in segments if s[1]]
    if not segs:
        raise ValueError("refusing to write an ELF with no segment data")

    phoff = EHDR_SIZE
    data_start = phoff + PHDR_SIZE * len(segs)

    # Keep p_offset congruent to p_vaddr modulo the page size; ELF loaders are
    # entitled to assume it and some reject images where it does not hold.
    offsets: list[int] = []
    cursor = data_start
    for load_addr, blob, _x in segs:
        aligned = cursor + ((load_addr - cursor) % PAGE)
        offsets.append(aligned)
        cursor = aligned + len(blob)

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9,  # ELF32, LE, SysV
        ET_EXEC,
        EM_XTENSA,
        1,  # EV_CURRENT
        entry,
        phoff,
        0,  # e_shoff: no section headers
        0,  # e_flags
        EHDR_SIZE,
        PHDR_SIZE,
        len(segs),
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )

    phdrs = b""
    for (load_addr, blob, executable), off in zip(segs, offsets, strict=True):
        flags = PF_R | (PF_X if executable else PF_W)
        phdrs += struct.pack(
            "<IIIIIIII",
            PT_LOAD,
            off,
            load_addr,  # p_vaddr
            load_addr,  # p_paddr
            len(blob),  # p_filesz
            len(blob),  # p_memsz
            flags,
            PAGE,
        )

    body = bytearray()
    for (_load_addr, blob, _x), off in zip(segs, offsets, strict=True):
        pad = off - (data_start + len(body))
        body.extend(b"\x00" * pad)
        body.extend(blob)

    out.write_bytes(ehdr + phdrs + bytes(body))
    return out


SHDR_SIZE = 40
SHT_NULL, SHT_PROGBITS, SHT_STRTAB = 0, 1, 3
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4


def write_sectioned_elf(
    path: str | Path, sections: list[tuple[str, int, bytes]]
) -> Path:
    """Write an ELF with one executable section per (name, vaddr, data).

    objdump restarts its linear sweep at every section boundary, so putting each
    function in its own section makes one objdump invocation decode all of them
    *from their own entry points* — which is the only alignment that is correct
    for a function. A single sweep across a whole segment desynchronizes on the
    first literal pool and then mis-decodes everything after it.
    """
    out = Path(path)
    if not sections:
        raise ValueError("refusing to write an ELF with no sections")

    names = [".shstrtab"] + [n for n, _v, _d in sections]
    strtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for n in names:
        name_offsets[n] = len(strtab)
        strtab.extend(n.encode() + b"\x00")

    # Layout: ehdr, section data (4-byte aligned), shstrtab, section headers.
    offsets: list[int] = []
    cursor = EHDR_SIZE
    for _n, _v, blob in sections:
        cursor += -cursor % 4
        offsets.append(cursor)
        cursor += len(blob)
    cursor += -cursor % 4
    strtab_off = cursor
    cursor += len(strtab)
    cursor += -cursor % 4
    shoff = cursor

    shnum = len(sections) + 2  # NULL + sections + shstrtab
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9,
        ET_EXEC,
        EM_XTENSA,
        1,
        sections[0][1],
        0,  # e_phoff: no program headers
        shoff,
        0,
        EHDR_SIZE,
        0,
        0,
        SHDR_SIZE,
        shnum,
        shnum - 1,  # e_shstrndx: shstrtab is last
    )

    shdrs = struct.pack("<IIIIIIIIII", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
    for (name, vaddr, blob), off in zip(sections, offsets, strict=True):
        shdrs += struct.pack(
            "<IIIIIIIIII",
            name_offsets[name],
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            vaddr,
            off,
            len(blob),
            0,
            0,
            4,
            0,
        )
    shdrs += struct.pack(
        "<IIIIIIIIII",
        name_offsets[".shstrtab"],
        SHT_STRTAB,
        0,
        0,
        strtab_off,
        len(strtab),
        0,
        0,
        1,
        0,
    )

    buf = bytearray(ehdr)
    for (_n, _v, blob), off in zip(sections, offsets, strict=True):
        buf.extend(b"\x00" * (off - len(buf)))
        buf.extend(blob)
    buf.extend(b"\x00" * (strtab_off - len(buf)))
    buf.extend(strtab)
    buf.extend(b"\x00" * (shoff - len(buf)))
    buf.extend(shdrs)

    out.write_bytes(bytes(buf))
    return out


SHF_WRITE = 0x1


def write_program_elf(
    path: str | Path,
    segments: list[tuple[str, int, bytes, bool]],
    entry: int = 0,
) -> Path:
    """Write an Xtensa ELF of `segments` as named, permissioned sections.

    `write_elf` produces the minimum a loader needs: program headers and bytes.
    That is enough to *import* an image, and it is all boundary recovery ever
    needed internally. What it does not give an analyst is a map — every block
    arrives unnamed, and nothing says which are executable.

    So this adds section headers, and nothing else. A disassembler names its
    memory blocks from them and reads permissions off them, which is the
    difference between opening a program whose blocks are called `.iram0.text`
    and `.flash.rodata` and opening six anonymous spans of bytes.

    It writes no symbol table. Where functions begin and what they are called is
    a separate question with a separate answer, produced against this file
    rather than baked into it.

    `segments` are `(section_name, load_addr, data, executable)`.
    """
    out = Path(path)
    segs = [s for s in segments if s[2]]
    if not segs:
        raise ValueError("refusing to write an ELF with no segment data")

    # Sections: NULL, one per segment, then .shstrtab.
    shstrtab = bytearray(b"\x00")
    sh_name_off: dict[str, int] = {}
    for name in [".shstrtab"] + [n for n, _a, _d, _x in segs]:
        sh_name_off[name] = len(shstrtab)
        shstrtab.extend(name.encode() + b"\x00")

    phoff = EHDR_SIZE
    data_start = phoff + PHDR_SIZE * len(segs)

    # p_offset must stay congruent to p_vaddr modulo the page size; loaders are
    # entitled to assume it and some reject images where it does not hold.
    offsets: list[int] = []
    cursor = data_start
    for _n, load_addr, blob, _x in segs:
        aligned = cursor + ((load_addr - cursor) % PAGE)
        offsets.append(aligned)
        cursor = aligned + len(blob)

    shstrtab_off = cursor
    cursor += len(shstrtab)
    cursor += -cursor % 4
    shoff = cursor

    shnum = len(segs) + 2  # NULL + segments + shstrtab
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9,  # ELF32, LE, SysV
        ET_EXEC,
        EM_XTENSA,
        1,  # EV_CURRENT
        entry,
        phoff,
        shoff,
        0,  # e_flags
        EHDR_SIZE,
        PHDR_SIZE,
        len(segs),
        SHDR_SIZE,
        shnum,
        shnum - 1,  # e_shstrndx: shstrtab is last
    )

    phdrs = b""
    for (_n, load_addr, blob, executable), off in zip(segs, offsets, strict=True):
        phdrs += struct.pack(
            "<IIIIIIII",
            PT_LOAD,
            off,
            load_addr,  # p_vaddr
            load_addr,  # p_paddr
            len(blob),  # p_filesz
            len(blob),  # p_memsz
            PF_R | (PF_X if executable else PF_W),
            PAGE,
        )

    shdrs = struct.pack("<IIIIIIIIII", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
    for (name, load_addr, blob, executable), off in zip(segs, offsets, strict=True):
        flags = SHF_ALLOC | (SHF_EXECINSTR if executable else SHF_WRITE)
        shdrs += struct.pack(
            "<IIIIIIIIII",
            sh_name_off[name],
            SHT_PROGBITS,
            flags,
            load_addr,
            off,
            len(blob),
            0,
            0,
            4,
            0,
        )
    shdrs += struct.pack(
        "<IIIIIIIIII",
        sh_name_off[".shstrtab"],
        SHT_STRTAB,
        0,
        0,
        shstrtab_off,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )

    buf = bytearray(ehdr + phdrs)
    for (_n, _a, blob, _x), off in zip(segs, offsets, strict=True):
        buf.extend(b"\x00" * (off - len(buf)))
        buf.extend(blob)
    buf.extend(b"\x00" * (shstrtab_off - len(buf)))
    buf.extend(shstrtab)
    buf.extend(b"\x00" * (shoff - len(buf)))
    buf.extend(shdrs)

    out.write_bytes(bytes(buf))
    return out
