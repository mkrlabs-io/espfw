"""Canonicalizer behaviour.

These assert the masking contract directly rather than through the pipeline, so
a canonicalizer regression is attributable without a corpus or a toolchain.
"""

from __future__ import annotations

from espfw.canon import CANON_VERSION
from espfw.canon.xtensa import CALL_MASK, LITERAL_MASK, canonicalize
from espfw.disasm.types import InsnClass, Instruction


def insn(addr, mnemonic, operands, cls=InsnClass.NORMAL, size=3, **kw):
    return Instruction(
        addr=addr, size=size, raw=b"\x00" * size, mnemonic=mnemonic,
        operands=list(operands), cls=cls, **kw
    )


def test_l32r_offset_is_masked_but_value_is_kept():
    """The masked immediate is what matching needs; the value is what
    config inference needs. Both must survive."""
    form = canonicalize([
        insn(0x100, "l32r", ["a3", "0x90"], InsnClass.LITERAL_LOAD,
             target=0x90, literal_value=0xDEADBEEF),
        insn(0x103, "ret", [], InsnClass.RETURN, size=3),
    ])
    assert LITERAL_MASK in form.canonical_text
    assert "0x90" not in form.canonical_text
    assert form.literals == [0xDEADBEEF]
    assert "0xdeadbeef" in form.raw_text


def test_call_targets_are_masked_but_recorded_as_edges():
    form = canonicalize([
        insn(0x100, "call8", ["0x4000"], InsnClass.CALL, target=0x4000),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    assert CALL_MASK in form.canonical_text
    assert "0x4000" not in form.canonical_text
    assert form.call_targets == [0x4000]


def test_branch_targets_become_relative_so_position_does_not_matter():
    """Two copies of the same function at different addresses must canonicalize
    identically, while genuinely different control flow must not."""
    def build(base):
        return canonicalize([
            insn(base, "entry", ["a1", "32"], InsnClass.ENTRY),
            insn(base + 3, "beqz", ["a2", hex(base + 9)], InsnClass.BRANCH,
                 target=base + 9),
            insn(base + 6, "nop", []),
            insn(base + 9, "retw.n", [], InsnClass.RETURN, size=2),
        ])

    assert build(0x400D0000).digest == build(0x40085000).digest

    different = canonicalize([
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "beqz", ["a2", "0x106"], InsnClass.BRANCH, target=0x106),
        insn(0x106, "nop", []),
        insn(0x109, "retw.n", [], InsnClass.RETURN, size=2),
    ])
    assert different.digest != build(0x400D0000).digest


def test_longcall_pairs_become_call_edges():
    """ESP-IDF builds with -mlongcalls, so most calls are l32r + callx8.
    Treating those as opaque indirect calls would lose the call graph."""
    form = canonicalize([
        insn(0x100, "l32r", ["a8", "0x80"], InsnClass.LITERAL_LOAD,
             target=0x80, literal_value=0x400D1234),
        insn(0x103, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x106, "retw.n", [], InsnClass.RETURN, size=2),
    ])
    assert form.call_targets == [0x400D1234]
    assert form.indirect_calls == 0


def test_genuinely_indirect_calls_stay_unresolved_not_dropped():
    """Record as an unresolved edge rather than dropping it."""
    form = canonicalize([
        insn(0x100, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x103, "retw.n", [], InsnClass.RETURN, size=2),
    ])
    assert form.indirect_calls == 1
    assert form.call_targets == []


def test_overwriting_a_register_invalidates_its_tracked_literal():
    form = canonicalize([
        insn(0x100, "l32r", ["a8", "0x80"], InsnClass.LITERAL_LOAD,
             target=0x80, literal_value=0x400D1234),
        insn(0x103, "mov", ["a8", "a2"]),
        insn(0x106, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x109, "retw.n", [], InsnClass.RETURN, size=2),
    ])
    assert form.call_targets == []
    assert form.indirect_calls == 1


def test_trailing_padding_is_stripped():
    """A symbol's st_size includes inter-function alignment padding; a recovered
    boundary ends at the last instruction. Both must canonicalize the same."""
    body = [
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "retw.n", [], InsnClass.RETURN, size=2),
    ]
    padded = [*body, insn(0x105, "nop", [], size=3)]
    assert canonicalize(body).digest == canonicalize(padded).digest


def test_ordinary_immediates_are_not_masked():
    """Masking every immediate would collapse genuinely different functions."""
    a = canonicalize([insn(0x100, "addi", ["a1", "a1", "-32"]),
                      insn(0x103, "ret", [], InsnClass.RETURN)])
    b = canonicalize([insn(0x100, "addi", ["a1", "a1", "-64"]),
                      insn(0x103, "ret", [], InsnClass.RETURN)])
    assert a.digest != b.digest
    assert -32 in a.immediates


def test_digest_is_bound_to_the_canonicalizer_version():
    """Results computed under different rules must never compare equal."""
    import espfw.canon as canon_pkg

    form = canonicalize([insn(0x100, "ret", [], InsnClass.RETURN)])
    original = canon_pkg.CANON_VERSION
    try:
        canon_pkg.CANON_VERSION = original + 1
        bumped = canonicalize([insn(0x100, "ret", [], InsnClass.RETURN)])
    finally:
        canon_pkg.CANON_VERSION = original
    assert form.canonical_text == bumped.canonical_text
    assert form.digest != bumped.digest


def test_windowed_and_call0_prologues_are_distinguished():
    windowed = canonicalize([
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "retw.n", [], InsnClass.RETURN, size=2),
    ])
    call0 = canonicalize([
        insn(0x100, "addi", ["a1", "a1", "-16"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    assert windowed.prologue == "windowed"
    assert call0.prologue == "call0"


def test_empty_input_is_handled():
    form = canonicalize([])
    assert form.instruction_count == 0
    assert form.digest


def test_canon_version_is_an_int():
    assert isinstance(CANON_VERSION, int)


# --- v3: absorbing what the linker does --------------------------------


def test_density_encoding_is_folded():
    """Relaxation narrows instructions the assembler emitted wide, so the
    archive and the image disagree on encoding for identical source."""
    wide = canonicalize([
        insn(0x100, "s32i", ["a15", "a1", "8"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    narrow = canonicalize([
        insn(0x100, "s32i.n", ["a15", "a1", "8"], size=2),
        insn(0x102, "ret.n", [], InsnClass.RETURN, size=2),
    ])
    assert wide.digest == narrow.digest
    # The raw view keeps the encoding actually present in the bytes.
    assert "s32i.n" in narrow.raw_text
    assert "s32i.n" not in narrow.canonical_text


def test_or_move_idiom_is_folded():
    idiom = canonicalize([
        insn(0x100, "or", ["a10", "a2", "a2"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    explicit = canonicalize([
        insn(0x100, "mov", ["a10", "a2"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    assert idiom.digest == explicit.digest


def test_or_that_is_not_a_move_is_left_alone():
    real_or = canonicalize([
        insn(0x100, "or", ["a10", "a2", "a3"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    move = canonicalize([
        insn(0x100, "mov", ["a10", "a2"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    assert real_or.digest != move.digest


def test_interior_alignment_padding_is_dropped():
    """The linker inserts `or a1,a1,a1` between blocks; the archive has none."""
    padded = canonicalize([
        insn(0x100, "addi", ["a2", "a2", "1"]),
        insn(0x103, "or", ["a1", "a1", "a1"]),
        insn(0x106, "nop", []),
        insn(0x109, "ret", [], InsnClass.RETURN),
    ])
    clean = canonicalize([
        insn(0x100, "addi", ["a2", "a2", "1"]),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ])
    assert padded.digest == clean.digest
    # Still reconstructible: the bytes that were there are in the raw view.
    assert "or a1 a1 a1" in padded.raw_text


def test_longcall_sequence_matches_the_relaxed_direct_call():
    """`l32r aN, lit; callx8 aN` is what -mlongcalls emits; `call8` is what the
    linker rewrites it into. The corpus holds the first and images hold the
    second, so they have to canonicalize alike."""
    longcall = canonicalize([
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "l32r", ["a8", "0x200"], InsnClass.LITERAL_LOAD,
             target=0x200, literal_value=0x400D1234),
        insn(0x106, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x109, "retw", [], InsnClass.RETURN),
    ])
    direct = canonicalize([
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "call8", ["0x400d1234"], InsnClass.CALL, target=0x400D1234),
        insn(0x106, "retw", [], InsnClass.RETURN),
    ])
    assert longcall.digest == direct.digest
    assert longcall.call_targets == [0x400D1234]
    assert longcall.indirect_calls == 0


def test_a_genuinely_indirect_call_is_not_collapsed():
    """A callx whose register was not loaded by a literal is a real indirect
    call — collapsing it would invent a call graph edge that does not exist."""
    form = canonicalize([
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "l32i", ["a8", "a2", "0"]),
        insn(0x106, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x109, "retw", [], InsnClass.RETURN),
    ])
    assert form.indirect_calls == 1
    assert form.call_targets == []
    assert "callx8" in form.canonical_text


def test_separated_literal_and_callx_are_not_collapsed():
    """Only an adjacent pair is the relaxable sequence. With an instruction in
    between, the linker's rewrite is not a two-for-one and pretending otherwise
    would drop a real instruction from the form."""
    form = canonicalize([
        insn(0x100, "l32r", ["a8", "0x200"], InsnClass.LITERAL_LOAD,
             target=0x200, literal_value=0x400D1234),
        insn(0x103, "addi", ["a2", "a2", "1"]),
        insn(0x106, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x109, "ret", [], InsnClass.RETURN),
    ])
    assert "l32r" in form.canonical_text
    assert "callx8" in form.canonical_text
    # The edge is still recovered — only the textual collapse is declined.
    assert form.call_targets == [0x400D1234]


def test_strings_are_recorded_but_never_hashed():
    """An anchor that changed the canonical form would stop being an anchor."""
    insns = [
        insn(0x100, "l32r", ["a3", "0x200"], InsnClass.LITERAL_LOAD,
             target=0x200, literal_value=0x3F400100),
        insn(0x103, "ret", [], InsnClass.RETURN),
    ]
    without = canonicalize(insns)
    with_strings = canonicalize(insns, read_cstr=lambda _addr: "wifi: connected")
    assert with_strings.strings == ["wifi: connected"]
    assert without.strings == []
    assert with_strings.digest == without.digest


def test_canon_version_is_stamped_into_every_digest():
    form = canonicalize([insn(0x100, "ret", [], InsnClass.RETURN)])
    assert CANON_VERSION == 3
    assert form.digest != _digest_without_version(form.canonical_text)


def _digest_without_version(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


def test_collapse_does_not_depend_on_the_pool_being_readable():
    """Whether a literal pool is reachable depends on how much of the image was
    decoded. A canonical form that moved with the decoding context would not be
    canonical, so the collapse keys on the instruction pattern alone."""
    pattern = [
        insn(0x100, "entry", ["a1", "32"], InsnClass.ENTRY),
        insn(0x103, "l32r", ["a8", "0x200"], InsnClass.LITERAL_LOAD, target=0x200),
        insn(0x106, "callx8", ["a8"], InsnClass.CALL_INDIRECT),
        insn(0x109, "retw", [], InsnClass.RETURN),
    ]
    unresolved = canonicalize(pattern)
    resolved = canonicalize([
        pattern[0],
        insn(0x103, "l32r", ["a8", "0x200"], InsnClass.LITERAL_LOAD,
             target=0x200, literal_value=0x400D1234),
        pattern[2],
        pattern[3],
    ])
    assert unresolved.digest == resolved.digest
    # Only the recovered edge differs, which is honest: one is knowable.
    assert resolved.call_targets == [0x400D1234]
    assert unresolved.call_targets == []
    assert unresolved.indirect_calls == 0
