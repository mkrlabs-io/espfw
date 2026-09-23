"""Harvest signatures from build artifacts.

Two sources, deliberately both:

- **The intermediate `.a` archives.** A hello-world app linked with
  --gc-sections pulls in a small slice of the SDK; the archives carry full
  symbol tables and every function, an order of magnitude more coverage for the
  same build. Also fingerprints the precompiled blobs (libphy, libnet80211,
  librtc), which ship as binaries and are bit-identical everywhere.
- **The linked ELF.** Archives have not been through linker relaxation, and
  Xtensa relaxation genuinely rewrites call sequences at link time. Code in a
  real firmware image has been relaxed, so the linked ELF is the higher-fidelity
  reference where it is available — at much lower coverage.

Both are stored with their origin recorded, and the matcher prefers `linked`
when a function is present in both. Silently mixing them would make a
relaxation difference look like a modification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from espfw import elfreader
from espfw.canon.xtensa import CALL_MASK, CanonicalForm, canonicalize
from espfw.disasm import disassemble_ranges
from espfw.strings import cstr_at

_LIB_RE = re.compile(r"^lib(.+)\.a$")


@dataclass(slots=True)
class HarvestedFunction:
    name: str
    component: str | None
    object: str | None
    origin: str
    vaddr: int | None
    form: CanonicalForm


def component_of(archive_path: str | Path) -> str:
    """`libfreertos.a` -> `freertos`."""
    stem = Path(archive_path).name
    m = _LIB_RE.match(stem)
    return m.group(1) if m else Path(stem).stem


def _extract(elf: elfreader.Elf32) -> list[tuple[str, int, bytes]]:
    """(name, vaddr, bytes) for every sized function symbol in `elf`."""
    by_name = {s.name: s for s in elf.sections}
    out: list[tuple[str, int, bytes]] = []
    seen: set[str] = set()

    for sym in elf.functions():
        if sym.name in seen:
            continue
        sec = by_name.get(sym.section or "")
        if sec is None or not sec.is_code:
            continue
        body = sec.data()
        # In a relocatable object the symbol value is an offset within its
        # section; in a linked image the section carries a real address and the
        # symbol value is absolute. Subtracting sh_addr handles both.
        off = sym.value - sec.addr
        if off < 0 or off + sym.size > len(body):
            continue
        out.append((sym.name, sym.value, body[off : off + sym.size]))
        seen.add(sym.name)
    return out


def harvest_elf(
    chip: str,
    data: bytes,
    origin: str,
    component: str | None = None,
    object_name: str | None = None,
    origin_label: str = "<memory>",
) -> list[HarvestedFunction]:
    """Harvest every function from one ELF image held in memory."""
    try:
        elf = elfreader.Elf32(data, origin=origin_label)
    except elfreader.ElfError:
        return []
    if elf.e_machine != elfreader.EM_XTENSA:
        return []

    entries = _extract(elf)
    if not entries:
        return []

    decoded = disassemble_ranges(
        chip, [(f"{i}", vaddr, blob) for i, (_n, vaddr, blob) in enumerate(entries)]
    )

    # Each function is decoded from its own bytes, so objdump cannot see the
    # literal pool that its l32r loads point at — the pool lives in another
    # section. Resolving against the whole ELF recovers those values, which is
    # what turns -mlongcalls `l32r`+`callx8` pairs back into call-graph edges.
    _resolve_against_elf(elf, decoded)
    read_cstr = _cstr_reader(elf)
    # vaddr -> name, so a stored call edge names its callee rather than
    # keeping the masked placeholder.
    name_at = {
        sym.value: sym.name for sym in elf.functions() if sym.value
    }

    out: list[HarvestedFunction] = []
    for i, (name, vaddr, _blob) in enumerate(entries):
        insns = decoded.get(str(i))
        if not insns:
            continue
        form = canonicalize(insns, base_addr=vaddr, read_cstr=read_cstr)
        resolved = [name_at.get(t) for t in form.call_targets]
        if any(resolved):
            # Unresolvable targets keep the placeholder rather than being
            # dropped, so the edge list stays aligned with the call sites.
            form.call_edges = [n or CALL_MASK for n in resolved]
        out.append(
            HarvestedFunction(
                name=name,
                component=component,
                object=object_name,
                origin=origin,
                vaddr=vaddr,
                form=form,
            )
        )
    return out


def _cstr_reader(elf: elfreader.Elf32):
    """Resolve an address to the NUL-terminated string there, if any.

    Only allocated non-code sections are consulted: a "string" read out of the
    text segment is an instruction sequence that happens to be printable.
    """
    regions = [
        (sec.addr, sec.data())
        for sec in elf.sections
        if sec.is_alloc and not sec.is_code and sec.addr and sec.size
    ]

    def read(addr: int) -> str | None:
        for base, blob in regions:
            if base <= addr < base + len(blob):
                return cstr_at(blob, addr - base)
        return None

    return read


def _resolve_against_elf(elf: elfreader.Elf32, decoded: dict[str, list]) -> None:
    """Fill in l32r literal values by reading the ELF's allocated sections.

    In a relocatable object the pool entries are zero placeholders awaiting
    relocation, so this resolves nothing there — correctly, since the value is
    genuinely not known until link time.
    """
    from espfw.disasm.types import InsnClass

    mapped = [
        (s.addr, s.data())
        for s in elf.sections
        if s.is_alloc and s.addr and s.data()
    ]
    if not mapped:
        return

    for insns in decoded.values():
        for insn in insns:
            if insn.cls is not InsnClass.LITERAL_LOAD or insn.target is None:
                continue
            if insn.literal_value is not None:
                continue
            for addr, blob in mapped:
                off = insn.target - addr
                if 0 <= off <= len(blob) - 4:
                    insn.literal_value = int.from_bytes(blob[off : off + 4], "little")
                    break


def harvest_archive(chip: str, path: str | Path) -> list[HarvestedFunction]:
    """Harvest every function from every object in a `.a` archive."""
    p = Path(path)
    data = p.read_bytes()
    try:
        members = elfreader.ar_members(data)
    except elfreader.ElfError:
        return []

    component = component_of(p)
    out: list[HarvestedFunction] = []
    for member_name, body in members:
        if not elfreader.is_elf(body):
            continue
        out.extend(
            harvest_elf(
                chip,
                body,
                origin="archive",
                component=component,
                object_name=member_name,
                origin_label=f"{p.name}({member_name})",
            )
        )
    return out


def harvest_linked_elf(chip: str, path: str | Path) -> list[HarvestedFunction]:
    """Harvest from the linked application ELF (post-relaxation reference)."""
    p = Path(path)
    return harvest_elf(
        chip,
        p.read_bytes(),
        origin="linked",
        component=None,
        object_name=p.name,
        origin_label=str(p),
    )
