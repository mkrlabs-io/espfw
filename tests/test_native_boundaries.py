"""In-tool boundary recovery tests.

Every case here is hand-assembled Xtensa, so what is being tested is the
descent's judgement rather than any particular firmware. The end-to-end accuracy
numbers come from `tests/test_integration.py` and
`scripts/measure_rom_boundaries.py`, where the ground truth is a real symbol
table.

Skipped without an Xtensa toolchain: recovery decodes through objdump and
nothing may substitute another decoder, so with none installed there is nothing to
test rather than something to approximate.
"""

from __future__ import annotations

import subprocess

import pytest

from espfw.boundaries import native
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

BASE = 0x40080000

ENTRY_A1 = bytes.fromhex("364100")  # entry a1, 32
ENTRY_A11 = bytes.fromhex("364b00")  # entry a11, 32 — same opcode, wrong register
RETW_N = bytes.fromhex("1df0")
RET_N = bytes.fromhex("0df0")
CALL0_PLUS_8 = bytes.fromhex("450000")  # from BASE+3, targets BASE+8

LEAF = ENTRY_A1 + RETW_N  # 5 bytes
PAD = b"\x00"  # what the linker aligns with, and what `ill` decodes from


def _recover(code: bytes, entry_addr: int | None = None, data: bytes = b""):
    spans = [native.Span(BASE, code, region="iram", executable=True)]
    if data:
        spans.append(native.Span(0x3FFB0000, data, region="dram", executable=False))
    return native.recover("esp32", spans, entry_addr=entry_addr)


@needs_toolchain
def test_a_windowed_prologue_is_found_without_being_called():
    """The scan is the point: nothing calls this, and it is still recovered."""
    result = _recover(LEAF)
    assert [f.entry for f in result.functions] == [BASE]
    assert result.functions[0].origins == [native.ORIGIN_PROLOGUE_SCAN]


@needs_toolchain
def test_entry_on_a_register_other_than_a1_is_not_a_function():
    """`entry` allocates the callee's frame, so it is always on the stack
    pointer. A byte pattern that decodes as `entry a11` is a coincidence in the
    middle of real code; admitting those cost 7 points of precision."""
    result = _recover(ENTRY_A11 + RETW_N)
    assert result.functions == []
    assert result.seeds_rejected >= 1


@needs_toolchain
def test_a_function_ends_where_the_next_begins_padding_excluded():
    """A symbol's `st_size` stops at the last instruction; the alignment bytes
    after it belong to no function. Claiming them would put every recovered
    boundary a few bytes off its own reference, which reads downstream as an
    SDK function that "isn't there"."""
    result = _recover(LEAF + PAD * 3 + LEAF)
    assert [f.entry for f in result.functions] == [BASE, BASE + 8]
    first = result.functions[0]
    assert first.span_end == BASE + len(LEAF), "alignment padding was claimed"
    assert first.size == len(LEAF)


@needs_toolchain
def test_a_direct_call_target_is_a_function_without_a_prologue():
    """Hand-written assembly (`_frxt_dispatch`, `_xt_context_save`) has no
    windowed prologue and is reached only by `call0`. The call is the proof."""
    code = ENTRY_A1 + CALL0_PLUS_8 + RETW_N + RET_N
    result = _recover(code, entry_addr=BASE)
    found = {f.entry: f for f in result.functions}
    assert BASE + 8 in found, "the call target was not recovered"
    assert found[BASE + 8].origins == [native.ORIGIN_DIRECT_CALL]
    assert native.ORIGIN_IMAGE_ENTRY in found[BASE].origins


@needs_toolchain
def test_a_pointer_from_data_reaches_an_uncalled_handler():
    """ISR handlers and driver-vtable members are never directly called, so a
    word in a data segment pointing at one is the only static evidence it is
    there. This is what the Ghidra-based path used to miss."""
    pointer = (BASE + 8).to_bytes(4, "little")
    result = _recover(LEAF + PAD * 3 + LEAF, data=pointer)
    handler = next(f for f in result.functions if f.entry == BASE + 8)
    assert native.ORIGIN_POINTER in handler.origins


@needs_toolchain
def test_an_unreached_tail_is_not_claimed_after_a_clean_return():
    """A body that ended on `retw.n` with every edge accounted for explains
    nothing about the bytes after it — those are code recovery missed, and
    swallowing them turned 22-byte `xt_unhandled_interrupt` into 1,273 bytes."""
    result = _recover(LEAF + PAD * 3 + PAD * 64)
    assert result.functions[0].span_end == BASE + len(LEAF)


@needs_toolchain
def test_flow_stops_at_an_illegal_instruction():
    """Xtensa encodes `ill` as zero bytes, which is also what the linker pads
    with. objdump decodes it as an ordinary instruction, so treating it as
    flow walks straight out of a function and through the padding after it."""
    result = _recover(ENTRY_A1 + PAD * 16 + LEAF)
    first = result.functions[0]
    assert first.span_end <= BASE + 3 + 2, first.span_end - BASE


@needs_toolchain
def test_reached_bytes_are_reported_separately_from_the_extent():
    """`size` is the extent, `ranges` is what control flow actually read. A
    reader has to be able to tell the claim from the evidence."""
    fn = _recover(LEAF, entry_addr=BASE).functions[0]
    raw = fn.as_raw()
    assert raw["size"] == fn.span_end - fn.entry
    assert raw["reached"] == sum(b - a for a, b in fn.ranges)


@needs_toolchain
def test_recovery_never_invokes_ghidra(monkeypatch):
    """espfw emits what goes into Ghidra and never drives it.

    Guarded by a test because this dependency was there once, and a subprocess
    is easy to reintroduce without noticing.
    """
    real_run = subprocess.run

    def guard(argv, *args, **kwargs):
        joined = " ".join(map(str, argv)) if isinstance(argv, list | tuple) else str(argv)
        assert "ghidra" not in joined.lower(), joined
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guard)
    assert _recover(LEAF, entry_addr=BASE).functions
