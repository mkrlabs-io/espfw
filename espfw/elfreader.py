"""Minimal ELF32 / `ar` archive reader.

Scope is deliberately narrow: section headers, symbol tables, and section
contents for little-endian ELF32, plus `ar` member extraction. That covers
every use in this tool — classifying an ELF input and harvesting functions
out of the `.a` archives.

This does *not* disassemble anything. All disassembly goes through
`espfw.disasm` and the Xtensa binutils.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

# e_machine
EM_XTENSA = 94
EM_RISCV = 243

# sh_type
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

# sh_flags
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# st_info >> 4 / & 0xf
STT_FUNC = 2
STT_OBJECT = 1


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int
    _data: bytes = field(repr=False, default=b"")

    @property
    def is_code(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def is_alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    def data(self) -> bytes:
        """Section contents; empty for NOBITS (.bss and friends)."""
        return b"" if self.sh_type == SHT_NOBITS else self._data


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int
    section: str | None = None

    @property
    def sym_type(self) -> int:
        return self.info & 0xF

    @property
    def is_func(self) -> bool:
        return self.sym_type == STT_FUNC

    @property
    def is_global(self) -> bool:
        return (self.info >> 4) != 0


class ElfError(Exception):
    pass


class Elf32:
    """A parsed little-endian ELF32 file."""

    def __init__(self, data: bytes, origin: str = "<memory>") -> None:
        if not data.startswith(ELF_MAGIC):
            raise ElfError(f"{origin}: not an ELF file")
        if data[4] != 1:
            raise ElfError(f"{origin}: only ELF32 is supported")
        if data[5] != 1:
            raise ElfError(f"{origin}: only little-endian ELF is supported")

        self.data = data
        self.origin = origin
        (
            self.e_type,
            self.e_machine,
            _version,
            self.e_entry,
            _e_phoff,
            e_shoff,
            _e_flags,
            _e_ehsize,
            _e_phentsize,
            _e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)

        self.sections: list[Section] = []
        if not e_shoff or not e_shnum:
            return

        raw: list[tuple[int, ...]] = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            raw.append(struct.unpack_from("<IIIIIIIIII", data, off))

        # The section-name string table has to be read before names resolve.
        shstr_off, shstr_size = raw[e_shstrndx][4], raw[e_shstrndx][5]
        shstrtab = data[shstr_off : shstr_off + shstr_size]

        for (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            _sh_info,
            _sh_addralign,
            sh_entsize,
        ) in raw:
            body = (
                b"" if sh_type == SHT_NOBITS else data[sh_offset : sh_offset + sh_size]
            )
            self.sections.append(
                Section(
                    name=_cstr(shstrtab, sh_name),
                    sh_type=sh_type,
                    flags=sh_flags,
                    addr=sh_addr,
                    offset=sh_offset,
                    size=sh_size,
                    link=sh_link,
                    entsize=sh_entsize,
                    _data=body,
                )
            )

    # -- accessors ------------------------------------------------------------

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def symbols(self) -> list[Symbol]:
        """All symbols from .symtab, with their owning section name resolved."""
        out: list[Symbol] = []
        for sec in self.sections:
            if sec.sh_type != SHT_SYMTAB:
                continue
            strtab = self.sections[sec.link].data() if sec.link < len(self.sections) else b""
            body = sec.data()
            entsize = sec.entsize or 16
            for off in range(0, len(body) - entsize + 1, entsize):
                st_name, st_value, st_size, st_info, _st_other, st_shndx = struct.unpack_from(
                    "<IIIBBH", body, off
                )
                name = _cstr(strtab, st_name)
                if not name:
                    continue
                owner = (
                    self.sections[st_shndx].name
                    if st_shndx < len(self.sections)
                    else None
                )
                out.append(
                    Symbol(
                        name=name,
                        value=st_value,
                        size=st_size,
                        info=st_info,
                        shndx=st_shndx,
                        section=owner,
                    )
                )
        return out

    def functions(self) -> list[Symbol]:
        """STT_FUNC symbols with a nonzero size, sorted by address.

        Zero-size FUNC symbols are dropped: they are usually assembly labels
        without a `.size` directive, and a zero-length function is not a usable
        signature source. They are still reachable via `symbols()`.
        """
        funcs = [s for s in self.symbols() if s.is_func and s.size > 0]
        funcs.sort(key=lambda s: (s.value, s.name))
        return funcs


def _longname(table: bytes, off: int) -> str:
    """Read one entry from the GNU `//` long-name table.

    Entries are terminated by "/\\n" — not by NUL, which is what the ELF string
    tables use. Reading them as C strings leaves a trailing "/\\n" glued to every
    long object name.
    """
    if off >= len(table):
        return ""
    end = table.find(b"/\n", off)
    if end < 0:
        end = table.find(b"\n", off)
    if end < 0:
        end = table.find(b"\x00", off)
    if end < 0:
        end = len(table)
    return table[off:end].decode("utf-8", "replace").rstrip("/")


def _cstr(buf: bytes, off: int) -> str:
    if off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    end = len(buf) if end < 0 else end
    return buf[off:end].decode("utf-8", "replace")


def load(path: str | Path) -> Elf32:
    p = Path(path)
    return Elf32(p.read_bytes(), origin=str(p))


def is_elf(data: bytes) -> bool:
    return data[:4] == ELF_MAGIC


# --- ar archives -------------------------------------------------------------

AR_MAGIC = b"!<arch>\n"


def ar_members(data: bytes) -> list[tuple[str, bytes]]:
    """Extract (name, contents) from a System V `ar` archive.

    Handles the GNU long-name table (`//` member plus `/<offset>` references),
    which every `.a` produced by binutils uses for the component object names
    we care about.
    """
    if not data.startswith(AR_MAGIC):
        raise ElfError("not an ar archive")

    pos = len(AR_MAGIC)
    longnames = b""
    out: list[tuple[str, bytes]] = []

    while pos + 60 <= len(data):
        header = data[pos : pos + 60]
        if header[58:60] != b"\x60\n":
            break
        raw_name = header[0:16].decode("ascii", "replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break
        body = data[pos + 60 : pos + 60 + size]
        pos += 60 + size + (size & 1)  # members are 2-byte aligned

        if raw_name == "//":
            longnames = body
            continue
        if raw_name in ("/", "/SYM64/", "__.SYMDEF"):
            continue  # the archive symbol index; we read symbols from the ELFs

        name = raw_name
        if name.startswith("/") and name[1:].isdigit():
            name = _longname(longnames, int(name[1:]))
        else:
            name = name.rstrip("/")
        out.append((name, body))

    return out
