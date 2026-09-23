"""The Xtensa canonicalizer.

Two representations are produced for every function, and both are kept:

- ``canonical``: operand-masked. Position-independent and link-independent, so
  the same source function built into different images produces the same form.
  This is what matching compares.
- ``raw``: full operand values, kept in the corpus so a matched function can
  be inspected or re-emitted without rebuilding anything.

What gets masked, and why:

- ``l32r`` literal-pool offsets are PC-relative into a pool that relocates, so
  the offset is masked. The pooled *value* is recorded in the raw view, because
  it is frequently a config-derived constant.
- Direct call targets depend on link order and are masked. The call itself is
  preserved as a graph edge.
- ``callx``/``jx`` indirect targets are invisible to static analysis. They are
  recorded as unresolved edges rather than dropped.
- Branch, jump and loop targets are rewritten as *relative* displacements.
  Relative form is position-independent while still encoding control-flow shape,
  so masking them outright would discard real discriminative information.
- Ordinary immediates (`addi a1, a1, -32`) are NOT masked. They are stable
  across builds of the same source, and masking every immediate would collapse
  genuinely different functions onto the same form.

Separately, the canonical form absorbs what the *linker* does to code, because
the corpus harvests functions before linking and every image contains them
after. Four transformations, each measured against archive/linked pairs
of the same function:

- **density encodings** are folded (`s32i.n` -> `s32i`), since relaxation
  narrows instructions that the assembler emitted wide;
- **`or aX, aY, aY` -> `mov aX, aY`**, the canonical Xtensa move idiom, which
  the two sides spell differently;
- **alignment padding is dropped anywhere**, not only at the end: the linker
  inserts `or a1, a1, a1` between basic blocks that the archive does not have;
- **`l32r aN, <lit>` + `callx8 aN` collapses to `call8 CALL`**, which is exactly
  what relaxation rewrites a -mlongcalls sequence into.

Without these, an archive signature and the same function as it appears in a
real image agree only 24.8% of the time; with them, 48.1%.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from espfw.disasm.types import InsnClass, Instruction

LITERAL_MASK = "LIT"
CALL_MASK = "CALL"

# Inter-function alignment padding. A symbol's `st_size` includes the padding
# that aligns the next function; a recovered boundary ends at the last real
# instruction. Same function, different byte count — so trailing padding is
# stripped on both sides before canonicalization, or every function harvested
# from a symbol table fails to match the same function recovered from an image.
_PADDING_MNEMONICS = {"nop", "nop.n", ".byte", ".short", ".word", "ill", "ill.n"}

# Density (narrow) encodings folded onto their wide spelling. The choice between
# them is the assembler's and the linker's, not the program's: relaxation
# rewrites wide instructions to narrow ones when the operands fit, so an archive
# and the image built from it disagree on encoding for identical source.
_NARROW_FORMS = {
    "add.n": "add",
    "addi.n": "addi",
    "beqz.n": "beqz",
    "bnez.n": "bnez",
    "break.n": "break",
    "l32i.n": "l32i",
    "mov.n": "mov",
    "movi.n": "movi",
    "nop.n": "nop",
    "ret.n": "ret",
    "retw.n": "retw",
    "s32i.n": "s32i",
}


def fold_mnemonic(mnemonic: str) -> str:
    return _NARROW_FORMS.get(mnemonic.lower(), mnemonic)


def _is_nop_line(mnemonic: str, ops: list[str]) -> bool:
    """`nop`, or the 24-bit nop the linker pads with, spelled `or a1, a1, a1`.

    Both are alignment, not program text. The linker inserts them between basic
    blocks where the archive has none, so keeping them makes the two forms of
    one function differ by whatever the aligner happened to need.
    """
    if mnemonic == "nop":
        return True
    return mnemonic == "mov" and len(ops) == 2 and ops[0] == ops[1] == "a1"


def strip_trailing_padding(insns: list[Instruction]) -> list[Instruction]:
    """Drop padding that follows the function's last real instruction.

    Only trailing padding is removed. Padding in the middle of a body is a
    signal that the boundary is wrong, and swallowing it would hide that.
    """
    end = len(insns)
    while end > 1 and insns[end - 1].mnemonic.lower() in _PADDING_MNEMONICS:
        end -= 1
    return insns[:end] if end else insns


@dataclass(slots=True)
class CanonicalForm:
    """The dual view of one function."""

    canonical_text: str
    digest: str
    """sha256 of (canonicalizer version, canonical text). The match key."""
    raw_text: str
    size: int
    instruction_count: int

    call_edges: list[str] = field(default_factory=list)
    """Direct call target symbol names, in order, when known (corpus side) —
    otherwise the masked placeholder."""
    call_targets: list[int] = field(default_factory=list)
    """Direct call target addresses, in order (target side)."""
    indirect_calls: int = 0
    branch_count: int = 0
    basic_block_hint: int = 0

    literals: list[int] = field(default_factory=list)
    """Resolved l32r pool values, in order. Raw view, for config inference."""
    immediates: list[int] = field(default_factory=list)
    """Numeric immediate operands, in order. Raw view."""

    strings: list[str] = field(default_factory=list)
    """String literals this function references, via l32r into a data region.
    Recorded, never hashed: they are context for a reader, not part of the
    match key."""

    prologue: str = "unknown"
    """'windowed', 'call0' or 'unknown' — the two ABIs produce wholly different
    prologues."""


def _is_number(tok: str) -> int | None:
    try:
        return int(tok, 0)
    except ValueError:
        return None


def canonicalize(
    instructions: list[Instruction],
    base_addr: int | None = None,
    read_cstr=None,
) -> CanonicalForm:
    """Canonicalize one function's instruction list.

    `instructions` must be decoded starting at the function's entry point; a
    decoding that began elsewhere is misaligned and will canonicalize to
    something meaningless rather than failing loudly.

    `read_cstr(addr) -> str | None` resolves a pooled literal to the string it
    points at, when one is supplied. The strings are recorded beside the form,
    never hashed into it.
    """
    from espfw.canon import CANON_VERSION

    insns = strip_trailing_padding(sorted(instructions, key=lambda i: i.addr))
    if not insns:
        empty = ""
        return CanonicalForm(
            canonical_text=empty,
            digest=_digest(CANON_VERSION, empty),
            raw_text=empty,
            size=0,
            instruction_count=0,
        )

    base = base_addr if base_addr is not None else insns[0].addr

    canon_lines: list[str] = []
    raw_lines: list[str] = []
    call_edges: list[str] = []
    call_targets: list[int] = []
    literals: list[int] = []
    immediates: list[int] = []
    strings: list[str] = []
    indirect_calls = 0
    branch_count = 0
    block_starts: set[int] = {base}

    # ESP-IDF compiles with -mlongcalls, so a call to anything out of direct
    # range is emitted as `l32r aN, <literal>` followed by `callx8 aN`. Treating
    # those as untracked indirect calls would throw away most of the call graph,
    # so the literal loaded into each register is tracked and paired with the
    # callx that consumes it.
    reg_literal: dict[str, int] = {}

    # canonical-line index of the `l32r` that last loaded each register, so a
    # `callx` consuming it can absorb that line into a single direct call.
    literal_line: dict[str, int] = {}

    for insn in insns:
        mnemonic = fold_mnemonic(insn.mnemonic)
        ops = list(insn.operands)
        raw_ops = list(insn.operands)

        # `or aX, aY, aY` is the Xtensa move idiom; the two sides of a link
        # spell it differently for identical source.
        if mnemonic == "or" and len(ops) == 3 and ops[1] == ops[2]:
            mnemonic, ops = "mov", [ops[0], ops[1]]

        if insn.cls is InsnClass.LITERAL_LOAD:
            if ops:
                ops[-1] = LITERAL_MASK
            # The line index is recorded whether or not the pool was readable:
            # the relaxable pattern is visible in the instructions alone, and
            # only the recovered call *target* needs the value.
            if ops:
                literal_line[insn.operands[0]] = len(canon_lines)
            if insn.literal_value is not None:
                literals.append(insn.literal_value)
                raw_ops[-1] = f"{insn.literal_value:#010x}"
                if ops:
                    reg_literal[insn.operands[0]] = insn.literal_value
                if read_cstr is not None:
                    text = read_cstr(insn.literal_value)
                    if text:
                        strings.append(text)
            elif ops:
                reg_literal.pop(insn.operands[0], None)

        elif insn.cls is InsnClass.CALL:
            if ops:
                ops[-1] = CALL_MASK
            call_edges.append(insn.target_symbol or CALL_MASK)
            if insn.target is not None:
                call_targets.append(insn.target)

        elif insn.cls is InsnClass.CALL_INDIRECT:
            # A callx whose register holds a known literal is a resolvable call,
            # not an unresolved edge.
            reg = insn.operands[0] if insn.operands else None
            resolved = reg_literal.get(reg) if reg else None

            # Relaxation rewrites `l32r aN, <lit>; callx8 aN` into a direct
            # `call8`. Collapsing the pair is what lets an archive signature
            # match the linked code in a real image; without it the two forms
            # differ by two instructions at every call site.
            #
            # The collapse keys on the *instruction pattern*, not on whether the
            # pooled value could be read. Whether a pool is reachable depends on
            # how much of the image was decoded, and a canonical form that moved
            # with the decoding context would not be canonical.
            line = literal_line.pop(reg, None) if reg else None
            collapsed = line is not None and line == len(canon_lines) - 1
            if collapsed:
                canon_lines.pop()
                width = insn.mnemonic[5:] or "8"
                mnemonic, ops = f"call{width}", [CALL_MASK]

            if resolved is not None:
                call_targets.append(resolved)
                call_edges.append(CALL_MASK)
                raw_ops = [f"{resolved:#010x}"]
                reg_literal.pop(reg, None)
            elif collapsed:
                # A relaxable call whose target we cannot name. It is a direct
                # call in the code, so counting it as indirect would understate
                # the call graph as much as inventing an edge would overstate it.
                call_edges.append(CALL_MASK)
            else:
                indirect_calls += 1

        elif insn.cls in (InsnClass.BRANCH, InsnClass.JUMP, InsnClass.LOOP):
            if insn.target is not None and ops:
                # Relative displacement: position-independent, but still carries
                # the control-flow shape that distinguishes functions.
                ops[-1] = f"{insn.target - insn.addr:+d}"
                block_starts.add(insn.target)
            if insn.cls is InsnClass.BRANCH:
                branch_count += 1
                block_starts.add(insn.addr + insn.size)

        else:
            for tok in ops:
                if (val := _is_number(tok)) is not None:
                    immediates.append(val)
            # Any other write to a register invalidates the literal we believed
            # it held. Xtensa's destination is the first operand.
            if insn.operands:
                reg_literal.pop(insn.operands[0], None)
                literal_line.pop(insn.operands[0], None)

        if _is_nop_line(mnemonic, ops):
            # Alignment, not program text. Recorded in the raw view so the
            # function's actual bytes remain reconstructible.
            raw_lines.append(
                f"{insn.addr:08x} {insn.mnemonic} {' '.join(raw_ops)}".strip()
            )
            continue

        canon_lines.append(f"{mnemonic} {' '.join(ops)}".strip())
        raw_lines.append(
            f"{insn.addr:08x} {insn.mnemonic} {' '.join(raw_ops)}".strip()
        )

    canonical_text = "\n".join(canon_lines)
    body_range = range(base, insns[-1].addr + insns[-1].size)

    head = insns[0]
    if head.cls is InsnClass.ENTRY or any(i.cls is InsnClass.RETURN and i.mnemonic.startswith("retw") for i in insns):
        prologue = "windowed"
    else:
        prologue = "call0"

    return CanonicalForm(
        canonical_text=canonical_text,
        digest=_digest(CANON_VERSION, canonical_text),
        raw_text="\n".join(raw_lines),
        size=sum(i.size for i in insns),
        instruction_count=len(insns),
        call_edges=call_edges,
        call_targets=call_targets,
        indirect_calls=indirect_calls,
        branch_count=branch_count,
        basic_block_hint=len([a for a in block_starts if a in body_range]),
        literals=literals,
        immediates=immediates,
        strings=strings,
        prologue=prologue,
    )


def _digest(version: int, text: str) -> str:
    """Hash the canonical text together with the canonicalizer version.

    Binding the version into the digest makes cross-version comparison
    impossible by construction rather than by convention: signatures produced
    under different rules can never accidentally collide as a match.
    """
    h = hashlib.sha256()
    h.update(f"espfw-canon-v{version}\n".encode())
    h.update(text.encode())
    return h.hexdigest()
