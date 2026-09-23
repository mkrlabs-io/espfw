"""Function boundary recovery: run the descent, grade the result, memoize it.

Recovery itself lives in `native.py`. What this module adds is grading: a
recovered boundary is not ground truth, so each one carries a confidence and
the evidence behind it — how the entry point was found, whether a prologue is
really there, whether control flow reached the whole extent it claims.

Xtensa hazards handled here: windowed (`entry`/`retw`) versus CALL0 prologues,
literal pools sitting inside or between functions, and inter-function padding.
"""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path

from espfw import cache, provenance
from espfw.boundaries import native
from espfw.boundaries.models import (
    BoundaryConfidence,
    BoundaryStats,
    FunctionBoundary,
    FunctionSet,
)
from espfw.disasm import (
    InsnClass,
    disassemble_binary,
    disassemble_ranges,
    objdump_version,
    resolve_literals,
)
from espfw.disasm.toolchain import find_objdump
from espfw.errors import EspfwError
from espfw.parse import parse_file
from espfw.parse.models import AppImage, ParseResult

# CALL0 prologues have no single defining instruction the way windowed code has
# `entry`; they open by making stack room and spilling the return address.
_CALL0_PROLOGUE_HEADS = {"addi", "addmi", "s32i", "s32i.n", "movi", "mov.n"}

# Share of a function's claimed extent that control flow has to reach before the
# gap is worth mentioning, and before it costs the boundary its grade. See
# `_build_function` for the measurement these come from.
_REACHED_REPORT = 0.90
_REACHED_PENALIZE = 0.50


def recover_functions(
    image_path: str | Path,
    slot: str | None = None,
    cache_dir: Path | None = None,
    refresh: bool = False,
) -> FunctionSet:
    """Recover the function list for the selected app image."""
    parsed = parse_file(image_path, select_slot=slot)
    if parsed.chip is None:
        raise EspfwError(
            "chip variant is unknown, so no disassembler can be selected",
            remedy="`flash-info` could not determine the chip. Boundary recovery "
            "cannot proceed without it.",
        )
    if parsed.selected_image is None:
        raise EspfwError("no application image was selected to analyse")

    img = parsed.images[parsed.selected_image]
    data = Path(parsed.path).read_bytes()

    key = _cache_key(parsed, img)
    cached = _load_cached(key, cache_dir) if not refresh else None
    if cached is not None:
        return cached

    result = _recover(parsed, img, data)
    _store_cached(key, result, cache_dir)
    return result


def _recover(parsed: ParseResult, img: AppImage, data: bytes) -> FunctionSet:
    chip = parsed.chip
    assert chip is not None

    segments = [s for s in img.segments if s.length > 0]
    if not segments:
        raise EspfwError("the selected image has no segment data to analyse")

    # Disassemble the executable segments end to end. Recovery does not read
    # this tiling — it decodes each basic block from its own leader instead, so
    # a literal pool cannot desynchronize it — but the canonicalizer resolves
    # l32r pool values against whole segments, and so does the literal pass
    # below.
    decoded = {}
    for seg in segments:
        if not seg.executable:
            continue
        blob = data[seg.file_offset : seg.file_offset + seg.length]
        decoded[seg.load_addr] = disassemble_binary(
            chip, blob, seg.load_addr, region=seg.region
        )

    warnings: list[str] = []
    if not decoded:
        warnings.append(
            "no segment loads into an executable region, so there is no code to "
            "recover boundaries from"
        )

    recovered = native.recover(
        chip,
        [
            native.Span(
                load_addr=seg.load_addr,
                data=data[seg.file_offset : seg.file_offset + seg.length],
                region=seg.region,
                executable=bool(seg.executable),
            )
            for seg in segments
        ],
        entry_addr=img.header.entry_addr,
    )
    raw_functions = [fn.as_raw() for fn in recovered.functions]
    decoded_fns = {fn.entry: fn.instructions for fn in recovered.functions}

    functions: list[FunctionBoundary] = []
    for raw in raw_functions:
        fn = _build_function(raw, img, decoded_fns.get(raw["entry"], []))
        if fn is not None:
            functions.append(fn)
    functions.sort(key=lambda f: f.entry)

    if recovered.rounds >= native.MAX_ROUNDS:
        warnings.append(
            f"the descent was still finding new code after {native.MAX_ROUNDS} "
            "rounds and was stopped; some functions are likely missing"
        )

    # l32r targets point into literal pools that may sit outside any single
    # function, so values are resolved against the full segments.
    resolve_literals(list(decoded.values()))
    _attach_literals(decoded_fns, decoded)

    stats = _compute_stats(functions, decoded)
    if stats.coverage_ratio < 0.7 and stats.total:
        warnings.append(
            f"boundary recovery claims only {stats.coverage_ratio:.0%} of executable "
            "bytes; downstream match rates will understate coverage, and a low "
            "match rate here means missed boundaries"
        )

    return FunctionSet(
        path=parsed.path,
        chip=chip,
        recovery_version=native.RECOVERY_VERSION,
        functions=functions,
        stats=stats,
        warnings=warnings,
        provenance=provenance.current(
            objdump_version=objdump_version(str(find_objdump(chip)))
        ),
    )


def decode_boundaries(
    chip: str, functions: list[FunctionBoundary], img: AppImage, data: bytes
) -> dict[int, list]:
    """Decode already-recovered boundaries, keyed by entry address.

    Canonicalization needs the instruction lists that boundary recovery
    produced, but `FunctionSet` is memoized as JSON and deliberately does not
    carry them. Re-decoding is one batched objdump call, and it guarantees the
    canonicalizer sees exactly the bytes the boundary was graded on.

    Literal values are attached here too. Each function is decoded from its own
    bytes, so objdump cannot see the pool its `l32r` loads point at — the pool
    lives in a neighbouring function's range. Without this the target side has
    no resolved literals at all, which silently costs the call graph its
    `l32r`+`callx` edges and leaves every string anchor unread.
    """
    decoded_fns = _decode_functions(
        chip,
        [{"entry": f.entry, "ranges": [list(r) for r in f.ranges]} for f in functions],
        img,
        data,
    )
    _attach_literals(decoded_fns, _decode_segments(chip, img, data))
    return decoded_fns


def _decode_segments(chip: str, img: AppImage, data: bytes) -> dict:
    """Whole executable segments, used only as a literal-pool oracle."""
    from espfw.disasm.objdump import disassemble_binary

    out = {}
    for seg in img.segments:
        if not seg.length:
            continue
        blob = data[seg.file_offset : seg.file_offset + seg.length]
        if len(blob) != seg.length:
            continue
        out[seg.load_addr] = disassemble_binary(
            chip, blob, seg.load_addr, region=seg.region
        )
    return out


def _decode_functions(
    chip: str, raw_functions: list[dict], img: AppImage, data: bytes
) -> dict[int, list]:
    """Disassemble each proposed function from its entry, one range at a time."""
    def seg_for(addr: int):
        return next(
            (s for s in img.segments if s.load_addr <= addr < s.load_addr + s.length),
            None,
        )

    requests: list[tuple[str, int, bytes]] = []
    for raw in raw_functions:
        ranges = raw.get("ranges") or []
        if not ranges:
            continue
        entry = raw["entry"]
        # Decode the contiguous span, not the individual ranges. Recovery
        # records only the runs control flow reached, and a symbol's st_size
        # covers the whole extent including whatever sits between them.
        # Spanning the gaps makes both sides cover identical bytes, which is
        # what exact matching requires — consistency between the two sides
        # matters more here than either side's opinion of the gaps.
        lo = min(a for a, _b in ranges)
        hi = max(b for _a, b in ranges)
        seg = seg_for(lo)
        if seg is None:
            continue
        start = seg.file_offset + (lo - seg.load_addr)
        end = min(start + (hi - lo), seg.file_offset + seg.length)
        if end > start:
            requests.append((str(entry), lo, data[start:end]))

    decoded = disassemble_ranges(chip, requests)

    out: dict[int, list] = {}
    for key, insns in decoded.items():
        out.setdefault(int(key), []).extend(insns)
    for insns in out.values():
        insns.sort(key=lambda i: i.addr)
    return out


def _build_function(raw: dict, img: AppImage, insns: list) -> FunctionBoundary | None:
    """Grade one recovered function.

    Three independent things can be wrong with a boundary, and they are kept
    apart because they mean different things to a reader:

    * **the entry point** — was it reached by a direct call, or only inferred?
    * **the prologue** — does a function actually start at that address?
    * **the extent** — did flow reach the bytes the function claims?

    A function can be certainly-a-function and still have an extent nobody
    verified (a `jx` switch table hides its own arms); downstream, that shows
    up as an SDK function that "isn't there".
    """
    entry = raw["entry"]
    ranges = [(a, b) for a, b in raw.get("ranges", [])]
    size = raw.get("size", 0)
    if size == 0 or not ranges:
        return None
    span_end = raw.get("span_end") or max(b for _a, b in ranges)
    origins = list(raw.get("origins", []))

    seg = next(
        (s for s in img.segments if s.load_addr <= entry < s.load_addr + s.length),
        None,
    )
    file_offset = seg.file_offset + (entry - seg.load_addr) if seg else None

    reasons: list[str] = []
    confidence = BoundaryConfidence.HIGH

    if not insns:
        return FunctionBoundary(
            entry=entry, file_offset=file_offset, size=size, ranges=ranges,
            span_end=span_end, name=None, region=seg.region if seg else None,
            is_thunk=bool(raw.get("thunk")),
            basic_blocks=raw.get("basic_blocks", 0),
            edges=raw.get("edges", 0),
            indirect_calls=raw.get("indirect_calls", 0),
            callees=list(raw.get("callees", [])),
            origins=origins,
            confidence=BoundaryConfidence.LOW,
            confidence_reasons=["no bytes could be decoded in this range"],
        )

    # How the entry point was found. A direct call is proof; everything else is
    # inference, and the reader is told which they have.
    if native.ORIGIN_IMAGE_ENTRY in origins:
        reasons.append("the image header's entry point")
    elif native.ORIGIN_DIRECT_CALL in origins:
        reasons.append("target of a direct `call`")
    elif native.ORIGIN_PROLOGUE_SCAN in origins:
        reasons.append("an `entry` prologue found by scanning, not called directly")
    elif native.ORIGIN_POINTER in origins:
        reasons.append("a pointer into code, not called directly")

    head = insns[0]
    if head.cls is InsnClass.ENTRY:
        reasons.append("windowed ABI prologue (`entry`)")
    elif head.mnemonic in _CALL0_PROLOGUE_HEADS:
        reasons.append(f"CALL0-style prologue (`{head.mnemonic}`)")
    else:
        confidence = _lower(confidence, BoundaryConfidence.MEDIUM)
        reasons.append(f"no recognizable prologue; body opens with `{head.mnemonic}`")

    tail = insns[-1]
    if tail.cls not in (InsnClass.RETURN, InsnClass.JUMP, InsnClass.JUMP_INDIRECT):
        confidence = _lower(confidence, BoundaryConfidence.MEDIUM)
        reasons.append(f"body ends on `{tail.mnemonic}`, not a return or tail jump")

    # Bytes claimed but never reached. This is the honest version of what the
    # old cross-check was reaching for: not "two engines disagree" but "this
    # much of the extent is unverified".
    #
    # It is reported, and mostly not penalized. Measured against the selftest
    # image's own symbols, an unreached share does not predict a wrong extent:
    # functions at 90-99% reached got the extent wrong 2 times in 326, against
    # 4 in 528 for those fully reached, and the 13 below 90% were all correct.
    # Small gaps are ordinary literal pools between basic blocks. The reason is
    # still stated well before the grade moves, so a reader can see how much of
    # the extent was actually read.
    reached = raw.get("reached", sum(b - a for a, b in ranges))
    share = reached / size if size else 1.0
    if share < _REACHED_REPORT:
        if share < _REACHED_PENALIZE:
            confidence = _lower(confidence, BoundaryConfidence.MEDIUM)
        reasons.append(
            f"control flow reached {reached:,} of the {size:,} bytes claimed "
            f"({share:.0%}); the rest sits behind an edge nothing can follow "
            "statically, so the extent is inferred from where the next function "
            "begins"
        )

    longest_run = _longest_data_run(insns)
    if longest_run > 3:
        confidence = _lower(confidence, BoundaryConfidence.MEDIUM)
        reasons.append(
            f"a {longest_run}-byte undecodable run sits inside the body — likely "
            "an interleaved literal pool spanned by the boundary"
        )

    return FunctionBoundary(
        entry=entry,
        file_offset=file_offset,
        size=size,
        ranges=ranges,
        span_end=span_end,
        name=None,
        region=seg.region if seg else None,
        is_thunk=bool(raw.get("thunk")),
        basic_blocks=raw.get("basic_blocks", 0),
        edges=raw.get("edges", 0),
        indirect_calls=raw.get("indirect_calls", 0),
        callees=list(raw.get("callees", [])),
        origins=origins,
        confidence=confidence,
        confidence_reasons=reasons,
    )


_CONF_RANK = {
    BoundaryConfidence.HIGH: 2,
    BoundaryConfidence.MEDIUM: 1,
    BoundaryConfidence.LOW: 0,
}


def _lower(a: BoundaryConfidence, b: BoundaryConfidence) -> BoundaryConfidence:
    return a if _CONF_RANK[a] <= _CONF_RANK[b] else b


def _longest_data_run(insns: list) -> int:
    """Longest contiguous run of undecodable bytes, in bytes."""
    longest = run = 0
    for insn in insns:
        if insn.cls is InsnClass.DATA:
            run += insn.size
            longest = max(longest, run)
        else:
            run = 0
    return longest


def _attach_literals(decoded_fns: dict, segments: dict) -> None:
    """Resolve l32r pool values for per-function decodings against full segments."""
    segs = list(segments.values())
    for insns in decoded_fns.values():
        for insn in insns:
            if insn.cls is not InsnClass.LITERAL_LOAD or insn.target is None:
                continue
            if insn.literal_value is not None:
                continue
            for seg in segs:
                if seg.contains(insn.target):
                    insn.literal_value = seg.word_at(insn.target)
                    break


def _compute_stats(functions: list[FunctionBoundary], decoded: dict) -> BoundaryStats:
    stats = BoundaryStats(total=len(functions))
    for f in functions:
        if f.confidence is BoundaryConfidence.HIGH:
            stats.high_confidence += 1
        elif f.confidence is BoundaryConfidence.MEDIUM:
            stats.medium_confidence += 1
        else:
            stats.low_confidence += 1
        if f.name:
            stats.named += 1
        if f.is_thunk:
            stats.thunks += 1
        stats.bytes_in_functions += f.size
        stats.bytes_reached += sum(b - a for a, b in f.ranges)
        for reason in f.confidence_reasons:
            if reason.startswith("windowed"):
                stats.windowed_prologues += 1
            elif reason.startswith("CALL0"):
                stats.call0_prologues += 1

    stats.bytes_executable = sum(seg.length for seg in decoded.values())
    if stats.bytes_executable:
        stats.coverage_ratio = round(
            stats.bytes_in_functions / stats.bytes_executable, 4
        )
    return stats


# --- memoization -------------------------------------------------------------


def _cache_key(parsed: ParseResult, img: AppImage) -> str:
    from espfw.canon import CANON_VERSION

    material = "|".join(
        [
            parsed.sha256,
            str(img.file_offset),
            parsed.chip or "?",
            native.RECOVERY_VERSION,
            str(CANON_VERSION),
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _load_cached(key: str, cache_dir: Path | None) -> FunctionSet | None:
    path = cache.boundaries_dir(cache_dir) / f"{key}.json"
    if not path.is_file():
        return None
    try:
        return FunctionSet.model_validate_json(path.read_text())
    except Exception:  # a cache entry is never worth failing over
        # Any unreadable, truncated or schema-drifted entry is simply recomputed.
        # This is a cache, so the only wrong behaviour would be trusting it.
        return None


def _store_cached(key: str, result: FunctionSet, cache_dir: Path | None) -> None:
    path = cache.boundaries_dir(cache_dir) / f"{key}.json"
    with contextlib.suppress(OSError):
        path.write_text(result.model_dump_json(indent=1))
