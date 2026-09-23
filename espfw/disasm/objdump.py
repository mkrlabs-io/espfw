"""Xtensa binutils objdump invocation and output parsing.

This module owns every disassembly in the tool. Both sides of every comparison
go through it — the corpus `.o` files and the target's raw segments — so that a
decoding difference can never masquerade as a different function.

Output shape (tab-separated, byte column printed big-endian-first):

    40007d54:\t012136        \tentry\ta1, 144

The byte column shows the instruction word most-significant-byte first, so it
is reversed to recover memory order.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from espfw.disasm.toolchain import find_objdump
from espfw.disasm.types import DisassembledSegment, InsnClass, Instruction
from espfw.errors import ToolchainError

_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t([0-9a-fA-F ]+?)\s*\t(\S+)(?:\s+(.*))?$")
_SYM_RE = re.compile(r"^([0-9a-fA-F]+)\s+<(.+)>:$")
# An address operand, optionally followed by the value objdump read at that
# address — `l32r a3, 0x40007c50 (0x3ffae014)` — and/or a symbol annotation.
_ADDR_OPERAND_RE = re.compile(
    r"^(0x[0-9a-fA-F]+|\d+)"
    r"(?:\s*\((0x[0-9a-fA-F]+)\))?"
    r"(?:\s*<([^>]+)>)?$"
)

CALL_DIRECT = {"call0", "call4", "call8", "call12"}
CALL_INDIRECT = {"callx0", "callx4", "callx8", "callx12"}
RETURNS = {"ret", "ret.n", "retw", "retw.n", "rfe", "rfi", "rfwo", "rfwu", "rfde"}
JUMPS = {"j", "j.l"}
JUMPS_INDIRECT = {"jx"}
LOOPS = {"loop", "loopnez", "loopgtz"}
ENTRIES = {"entry"}

# Every Xtensa conditional branch mnemonic starts with 'b' (beqz, bbci, bnall,
# ...). Enumerating them all is brittle across ISA options, so membership is by
# prefix, with the handful of non-branch 'b' mnemonics excluded explicitly.
_BRANCH_PREFIX = "b"
_NOT_BRANCHES = {"break", "break.n"}


def classify(mnemonic: str) -> InsnClass:
    m = mnemonic.lower()
    if m.startswith("."):
        return InsnClass.DATA
    if m in CALL_DIRECT:
        return InsnClass.CALL
    if m in CALL_INDIRECT:
        return InsnClass.CALL_INDIRECT
    if m in RETURNS:
        return InsnClass.RETURN
    if m in JUMPS:
        return InsnClass.JUMP
    if m in JUMPS_INDIRECT:
        return InsnClass.JUMP_INDIRECT
    if m in LOOPS:
        return InsnClass.LOOP
    if m in ENTRIES:
        return InsnClass.ENTRY
    if m == "l32r":
        return InsnClass.LITERAL_LOAD
    if m.startswith(_BRANCH_PREFIX) and m not in _NOT_BRANCHES:
        return InsnClass.BRANCH
    return InsnClass.NORMAL


def _parse_line(line: str) -> Instruction | None:
    m = _INSN_RE.match(line)
    if not m:
        return None
    addr_s, bytes_s, mnemonic, operand_s = m.groups()
    hexstr = bytes_s.replace(" ", "")
    if not hexstr or len(hexstr) % 2:
        return None
    # objdump prints the instruction word MSB-first; memory order is reversed.
    raw = bytes.fromhex(hexstr)[::-1]

    operands = [o.strip() for o in operand_s.split(",")] if operand_s else []
    cls = classify(mnemonic)

    target: int | None = None
    literal_value: int | None = None
    target_symbol: str | None = None
    if operands and cls in (
        InsnClass.CALL,
        InsnClass.JUMP,
        InsnClass.BRANCH,
        InsnClass.LOOP,
        InsnClass.LITERAL_LOAD,
    ):
        am = _ADDR_OPERAND_RE.match(operands[-1])
        if am:
            target = int(am.group(1), 0)
            if am.group(2):
                literal_value = int(am.group(2), 16)
            target_symbol = am.group(3)
            # Normalize the operand to the bare address so the raw rendering is
            # stable regardless of what annotations objdump chose to attach.
            operands[-1] = am.group(1)

    return Instruction(
        addr=int(addr_s, 16),
        size=len(raw),
        raw=raw,
        mnemonic=mnemonic,
        operands=operands,
        cls=cls,
        target=target,
        literal_value=literal_value,
        target_symbol=target_symbol,
    )


def _run(argv: list[str]) -> str:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=900, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolchainError(f"objdump failed: {exc}") from exc
    if proc.returncode != 0:
        raise ToolchainError(
            f"objdump exited {proc.returncode}: {proc.stderr.strip()[:400]}"
        )
    return proc.stdout


def disassemble_binary(
    chip: str, data: bytes, load_addr: int, region: str | None = None
) -> DisassembledSegment:
    """Disassemble a raw loaded segment at its true load address.

    The load address is not cosmetic: l32r targets and call targets are computed
    from it, and passing the wrong one produces confidently wrong operands
    rather than an error.
    """
    objdump = find_objdump(chip)
    with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
        tmp.write(data)
        tmp.flush()
        out = _run(
            [
                str(objdump),
                "-D",
                "-b", "binary",
                "-m", "xtensa",
                "-EL",
                "-z",  # do not collapse runs of zeroes; offsets must stay contiguous
                f"--adjust-vma={load_addr:#x}",
                tmp.name,
            ]
        )

    insns = [i for line in out.splitlines() if (i := _parse_line(line))]
    seg = DisassembledSegment(
        load_addr=load_addr,
        length=len(data),
        region=region,
        instructions=insns,
        data=data,
    )
    resolve_literals([seg])
    return seg


def disassemble_object(chip: str, path: str | Path) -> dict[str, list[Instruction]]:
    """Disassemble an ELF object file, grouped by function symbol.

    Used for corpus harvesting from the `.a` archives, where symbols are
    ground truth and boundaries do not have to be recovered.
    """
    objdump = find_objdump(chip)
    out = _run([str(objdump), "-d", "-z", str(path)])

    functions: dict[str, list[Instruction]] = {}
    current: list[Instruction] | None = None
    for line in out.splitlines():
        sym = _SYM_RE.match(line.strip())
        if sym:
            current = []
            functions[sym.group(2)] = current
            continue
        if current is None:
            continue
        if insn := _parse_line(line):
            current.append(insn)
    return {name: insns for name, insns in functions.items() if insns}


_SECTION_RE = re.compile(r"^Disassembly of section (\S+):$")


def disassemble_ranges(
    chip: str, ranges: list[tuple[str, int, bytes]], batch: int = 512
) -> dict[str, list[Instruction]]:
    """Disassemble each (key, vaddr, bytes) starting at its own entry point.

    A function must be decoded from its entry, not from wherever a sweep of the
    enclosing segment happened to land: Xtensa literal pools sit inside and
    between functions, and a sweep that runs into one desynchronizes and
    mis-decodes everything after it. Each range therefore becomes its own ELF
    section, and objdump restarts at every section boundary — so this costs one
    objdump invocation per batch rather than one per function.
    """
    from espfw.elfwriter import write_sectioned_elf

    objdump = find_objdump(chip)
    out: dict[str, list[Instruction]] = {}

    for start in range(0, len(ranges), batch):
        chunk = [r for r in ranges[start : start + batch] if r[2]]
        if not chunk:
            continue
        # Section names must be unique and are how results map back to keys.
        section_names = {f".espfw{i}": key for i, (key, _v, _d) in enumerate(chunk)}
        sections = [
            (name, vaddr, blob)
            for name, (key, vaddr, blob) in zip(section_names, chunk, strict=True)
        ]

        with tempfile.NamedTemporaryFile(suffix=".elf") as tmp:
            write_sectioned_elf(tmp.name, sections)
            text = _run([str(objdump), "-d", "-z", tmp.name])

        current: list[Instruction] | None = None
        for line in text.splitlines():
            sec = _SECTION_RE.match(line.strip())
            if sec:
                key = section_names.get(sec.group(1))
                current = out.setdefault(key, []) if key else None
                continue
            if current is None:
                continue
            if insn := _parse_line(line):
                current.append(insn)

    return out


def resolve_literals(segments: list[DisassembledSegment]) -> None:
    """Fill in `literal_value` for l32r loads whose pool is in a known segment.

    The masked l32r offset is what makes matching robust; the value it points at
    is often a config-derived constant. Both are kept.
    """
    for seg in segments:
        for insn in seg.instructions:
            if insn.cls is not InsnClass.LITERAL_LOAD or insn.target is None:
                continue
            if insn.literal_value is not None:
                continue  # objdump already read it out of this segment
            for other in segments:
                if other.contains(insn.target):
                    insn.literal_value = other.word_at(insn.target)
                    break
