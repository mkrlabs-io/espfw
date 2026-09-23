"""In-tool function boundary recovery by recursive descent.

Boundaries come from the same objdump decoding that the canonicalizer and
matcher consume, which is the only decoder espfw trusts. espfw never runs
Ghidra; it produces the ELF an analyst loads there.

**Recursive descent, never a linear sweep.** Xtensa puts literal pools inside
and between functions, and instructions are 2 or 3 bytes: a sweep that runs
into a pool desynchronizes and mis-decodes everything after it, confidently.
So every basic block is decoded from its own leader (`disassemble_ranges`
restarts objdump at each one), and only the instructions the control flow
actually reaches are admitted. Bytes nothing reaches are left unclaimed rather
than guessed at — that is what makes the coverage ratio meaningful.

**Where entry points come from is evidence, and it is kept.** Four sources,
which do not deserve equal trust:

| origin | what it is | trust |
|---|---|---|
| `image_entry` | the image header's entry address | certain |
| `direct_call` | the target of a `call0/4/8/12` | strong — the callee of a real call is a function, but the *call* can be a mis-decode |
| `prologue_scan` | an `entry` instruction found by byte scan | strong: `entry` is legal only at a windowed function's start |
| `pointer` | an aligned word, anywhere in the image, pointing into executable memory | weak on its own — confirmed only if a prologue decodes there |

The scans are what make this engine find code Ghidra's auto-analysis misses:
ISR handlers and driver-vtable members (`spi_flash_chip_*`) are never the target
of a direct call, so a call-graph-only traversal cannot reach them. On the ESP32
mask ROM — every function reached through a vector table or a dispatch struct —
that is the difference between 62% recall and 99.7%. The origin is recorded on
every function, so a reader can tell a called function from an inferred one.

Even a direct call is only as good as the instruction making it: bytes inside a
`jx` switch table that nothing ever decoded can decode, from the wrong offset, as
a `call` to an address that is not an instruction boundary at all.
`_cut_functions` resolves that in two tiers, and the header of that method is
where the measurement lives.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from espfw.disasm import InsnClass, Instruction, disassemble_ranges

RECOVERY_VERSION = "1"
"""Bumped when recovery changes shape enough that memoized boundaries from an
earlier version must not be reused. It is part of the boundary cache key."""

ORIGIN_IMAGE_ENTRY = "image_entry"
ORIGIN_DIRECT_CALL = "direct_call"
ORIGIN_PROLOGUE_SCAN = "prologue_scan"
ORIGIN_POINTER = "pointer"

# Origins that are proof of a function start on their own. A `pointer` or a
# `prologue_scan` seed still has to decode as a prologue before it is admitted.
_TRUSTED_ORIGINS = frozenset({ORIGIN_IMAGE_ENTRY, ORIGIN_DIRECT_CALL})

# First byte, in memory order, of `entry aN, imm`. objdump prints the word
# MSB-first (`012136` for `entry a1, 144`), so this is the low byte of that.
# `entry` is legal only as a windowed function's first instruction, which makes
# a byte scan for it a genuine boundary oracle rather than a heuristic.
ENTRY_OPCODE = 0x36

# Bytes decoded from a block leader in one objdump section. Only the leader's
# straight-line prefix is consumed, so this is a ceiling on wasted decoding, not
# on block length: a block that runs past it continues from a fresh leader.
CHUNK_BYTES = 256

# Descent rounds before giving up. Each round decodes the leaders discovered by
# the previous one, so this bounds the depth of the discovery chain rather than
# the work: a 131 kB firmware image converges in 23. Hitting the cap is reported
# as a warning, because it means code was still being found when we stopped.
MAX_ROUNDS = 40

# Cut/learn-noreturn/re-cut rounds. The loop exits as soon as the noreturn set
# stops changing, so this is only a guard against a set that oscillates; on a
# 131 kB image it settles at 21 functions well inside the budget.
NORETURN_PASSES = 6

# `ill` is the illegal-instruction opcode, and on Xtensa it is encoded as zero
# bytes — the same bytes the linker pads with. objdump decodes it as an ordinary
# instruction, so without this the descent falls straight through inter-function
# padding and out the other side, reading alignment as code.
HARD_STOP = frozenset({"ill", "ill.n"})

# CALL0 prologues have no single defining instruction the way windowed code has
# `entry`; they open by making stack room and spilling the return address. This
# is only ever consulted for *grading* a boundary, never for admitting one: the
# same instructions appear all over a function body, so a decode landing on one
# is no evidence at all that the address is a function start.
CALL0_PROLOGUE_HEADS = frozenset(
    {"addi", "addmi", "s32i", "s32i.n", "movi", "mov.n", "sub"}
)


@dataclass(slots=True)
class Span:
    """One loaded segment, as bytes at a virtual address."""

    load_addr: int
    data: bytes
    region: str | None = None
    executable: bool = False

    @property
    def end(self) -> int:
        return self.load_addr + len(self.data)

    def contains(self, addr: int) -> bool:
        return self.load_addr <= addr < self.end

    def slice_at(self, addr: int, length: int) -> bytes:
        off = addr - self.load_addr
        return self.data[off : off + length]


@dataclass(slots=True)
class RecoveredFunction:
    """A function the descent found, before confidence is graded."""

    entry: int
    size: int
    """The extent, `span_end - entry` — what a symbol's `st_size` states. The
    corpus side's boundaries come from symbols, so this is the number that has
    to mean the same thing on both sides of a match."""
    ranges: list[tuple[int, int]]
    """The runs control flow actually reached, which is a different claim: it is
    the evidence, and it can be a fraction of the extent when a `jx` switch
    table hides the arms. Kept separately so neither number has to stand in for
    the other."""
    span_end: int
    origins: list[str]
    is_thunk: bool = False
    never_returns: bool = False
    """No `ret` on any recovered path, from a body complete enough to say so.

    A body holding a `jx`, or one with an edge the descent never decoded, is not
    complete enough: the absence of a `ret` there says nothing about the
    function, only about how far recovery got. Both guards were paid for.
    Without the first, `_vfiprintf_r` was declared noreturn off the 832 of 7,265
    bytes flow reached; without the second, `esp_cpu_stall` was, off 122 of 135
    — and that one truncated `esp_restart_noos` at its call site, so its
    canonical form no longer matched anything. A wrong noreturn does not stay
    local; it spreads to every caller."""
    basic_blocks: int = 0
    edges: int = 0
    indirect_calls: int = 0
    callees: list[int] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)

    def as_raw(self) -> dict:
        """The engine-neutral dict `boundaries.run` grades and models."""
        return {
            "entry": self.entry,
            "name": None,
            "size": self.size,
            "reached": sum(b - a for a, b in self.ranges),
            "ranges": [list(r) for r in self.ranges],
            "span_end": self.span_end,
            "thunk": self.is_thunk,
            "basic_blocks": self.basic_blocks,
            "edges": self.edges,
            "indirect_calls": self.indirect_calls,
            "callees": self.callees,
            "origins": self.origins,
        }


@dataclass
class NativeResult:
    functions: list[RecoveredFunction]
    code: dict[int, Instruction]
    """Every instruction the descent reached, by address. This is the tiling the
    boundaries were cut from, so downstream never has to re-derive it."""
    rounds: int
    seeds_by_origin: dict[str, int]
    seeds_rejected: int
    """Candidate entries that decoded as something other than a function start.
    A large number here is not a failure — the pointer scan is deliberately
    over-inclusive and this is the filter doing its job."""
    noreturn: set[int] = field(default_factory=set)
    """Functions with no `ret` on any path — `abort`, `_xt_panic` and whatever
    reaches only them. Their callers do not fall through."""


def recover(
    chip: str, spans: list[Span], entry_addr: int | None = None
) -> NativeResult:
    """Recover functions from `spans` by recursive descent."""
    engine = _Descent(chip, spans)
    return engine.run(entry_addr)


class _Descent:
    def __init__(self, chip: str, spans: list[Span]) -> None:
        self.chip = chip
        self.spans = spans
        self.exec_spans = [s for s in spans if s.executable and s.data]
        self.code: dict[int, Instruction] = {}
        self.seeds: dict[int, set[str]] = {}
        self.pending: set[int] = set()
        self.decoded_from: set[int] = set()
        self.blocked: set[int] = set()
        self.rejected = 0
        self.noreturn: set[int] = set()
        self._pool_starts: list[int] = []
        self._pool_refs: dict[int, list[int]] = {}

    # --- address space -------------------------------------------------------

    def exec_span(self, addr: int) -> Span | None:
        for span in self.exec_spans:
            if span.contains(addr):
                return span
        return None

    # --- seeding -------------------------------------------------------------

    def add_seed(self, addr: int, origin: str) -> None:
        if addr % 4:
            # Every function start the linker emits is 4-byte aligned. Xtensa
            # instructions are not, so this rejects mid-instruction addresses
            # that a pointer scan would otherwise turn into phantom functions.
            return
        if self.exec_span(addr) is None:
            return
        self.seeds.setdefault(addr, set()).add(origin)
        self.pending.add(addr)

    def _seed_prologue_scan(self) -> None:
        """Every 4-aligned `entry` opcode in executable memory.

        Independent of the descent, so it reaches functions the call graph does
        not — and independent of any decoding, so a desynchronized sweep cannot
        hide one. Each hit is still decoded from its own address before it is
        believed.
        """
        for span in self.exec_spans:
            data = span.data
            for off in range(0, len(data) - 2, 4):
                if data[off] == ENTRY_OPCODE:
                    self.add_seed(span.load_addr + off, ORIGIN_PROLOGUE_SCAN)

    def _seed_pointers(self) -> None:
        """Aligned words anywhere in the image that point into executable memory.

        Literal pools, `.data` initializers, and the static tables ESP-IDF uses
        for ISR dispatch and flash-chip drivers all live here. Most hits are
        coincidence; `_confirm` decides.
        """
        for span in self.spans:
            data = span.data
            for off in range(0, len(data) - 3, 4):
                word = int.from_bytes(data[off : off + 4], "little")
                if word % 4 == 0 and self.exec_span(word) is not None:
                    self.add_seed(word, ORIGIN_POINTER)

    # --- descent -------------------------------------------------------------

    def run(self, entry_addr: int | None) -> NativeResult:
        if entry_addr is not None:
            self.add_seed(entry_addr, ORIGIN_IMAGE_ENTRY)
        self._seed_prologue_scan()
        self._seed_pointers()

        rounds = 0
        while self.pending and rounds < MAX_ROUNDS:
            rounds += 1
            self._descend_round()

        functions = self._cut_functions()
        by_origin: dict[str, int] = {}
        for origins in self.seeds.values():
            for origin in origins:
                by_origin[origin] = by_origin.get(origin, 0) + 1

        return NativeResult(
            functions=functions,
            code=self.code,
            rounds=rounds,
            seeds_by_origin=by_origin,
            seeds_rejected=self.rejected,
            noreturn=self.noreturn,
        )

    def _descend_round(self) -> None:
        todo = sorted(a for a in self.pending if a not in self.code)
        self.pending.clear()

        requests: list[tuple[str, int, bytes]] = []
        for addr in todo:
            if addr in self.decoded_from:
                continue
            span = self.exec_span(addr)
            if span is None:
                continue
            self.decoded_from.add(addr)
            blob = span.slice_at(addr, min(CHUNK_BYTES, span.end - addr))
            if blob:
                requests.append((str(addr), addr, blob))
        if not requests:
            return

        for insns in disassemble_ranges(self.chip, requests).values():
            self._ingest(insns)

    def _ingest(self, insns: list[Instruction]) -> None:
        """Admit a block leader's straight-line prefix, up to its terminator.

        Stopping at the terminator is what keeps the descent honest: bytes past
        it belong to whatever branches there, not to this decode, and claiming
        them is exactly how a linear sweep walks into a literal pool.
        """
        for insn in insns:
            if insn.addr in self.code:
                return
            if insn.mnemonic in HARD_STOP:
                # Not an edge we failed to follow — an edge that ends here.
                # `ill` is what the linker's zero padding decodes as, so a block
                # running into it has reached the end of its function, and must
                # not be read as incompletely recovered.
                #
                # Counting it as a gap instead measured 0.2 points better on
                # extent accuracy and was still rejected: it licenses extending
                # the extent to the next recovered entry, and where recovery
                # missed a function in between, the extension swallows it, and
                # an over-claimed body matches nothing. Two hundredths of a
                # percent does not buy that.
                self.blocked.add(insn.addr)
                return
            if insn.cls is InsnClass.DATA:
                # Undecodable bytes *inside* executable memory are a literal
                # pool, and the code resumes after it. That is a genuine gap in
                # the body — measured, treating it as an ending instead cost a
                # point of extent accuracy on the ROM.
                return
            self.code[insn.addr] = insn

            if insn.cls is InsnClass.CALL and insn.target is not None:
                self.add_seed(insn.target, ORIGIN_DIRECT_CALL)
            elif insn.cls in (InsnClass.BRANCH, InsnClass.LOOP):
                if insn.target is not None:
                    self.pending.add(insn.target)
            elif insn.cls is InsnClass.JUMP:
                if insn.target is not None:
                    self.pending.add(insn.target)
                return
            elif insn.cls in (InsnClass.RETURN, InsnClass.JUMP_INDIRECT):
                return

        # The block outran the chunk without terminating: continue from the end.
        if insns:
            self.pending.add(insns[-1].addr + insns[-1].size)

    # --- confirmation and extent --------------------------------------------

    def _mid_instruction(self) -> set[int]:
        """Addresses the descent decoded as being *inside* an instruction.

        An instruction can never start inside another one, so this is a sound
        rejection: a scan or pointer hit landing here is a coincidence in the
        middle of real code, not a function.
        """
        interior: set[int] = set()
        for addr, insn in self.code.items():
            interior.update(range(addr + 1, addr + insn.size))
        return interior

    def _confirm(self, addr: int, origins: set[str], interior: set[int]) -> bool:
        """Whether a seed is really a function start.

        A direct call proves it — the callee of a `call0/4/8/12` is a function
        by construction. A scan or pointer hit proves nothing by itself, so it
        must decode to `entry` at that exact address: the one Xtensa instruction
        that is legal *only* as a windowed function's first. Accepting a CALL0
        prologue here instead was measured and rejected — `addi`/`movi`/`s32i`
        occur constantly mid-body, and admitting them cost 7 points of precision
        while buying no recall on an IDF build, where 859 of 863 functions are
        windowed.
        """
        if origins & _TRUSTED_ORIGINS:
            return True
        if addr in interior:
            return False
        insn = self.code.get(addr)
        return insn is not None and _is_windowed_prologue(insn)

    def _cut_functions(self) -> list[RecoveredFunction]:
        interior = self._mid_instruction()
        self._pool_starts, self._pool_refs = self._literal_pools()

        # Tier 1: the seeds that decode to a real prologue at their own address.
        # Measured on this image, all 883 of them are true function starts, and
        # they alone are trusted to cut the first pass.
        prologue_backed = {
            addr: origins
            for addr, origins in self.seeds.items()
            if ORIGIN_IMAGE_ENTRY in origins
            or (
                addr not in interior
                and (insn := self.code.get(addr)) is not None
                and _is_windowed_prologue(insn)
            )
        }
        shadowed = self._incomplete_spans(prologue_backed)

        # Tier 2: a call target that is not itself a prologue. Six of the nine
        # in this image are real — hand-written assembly like `_frxt_dispatch`,
        # which has no windowed prologue and is reached only by `call0`. The
        # other three are the targets of `call` instructions that were never
        # real instructions: garbage bytes inside a `jx` function's unreachable
        # switch arms that happened to decode as a call. `shadowed` is what
        # separates them — a function start cannot lie inside the span of a
        # function whose own body is known to be incompletely recovered.
        confirmed: dict[int, set[str]] = {}
        for addr, origins in self.seeds.items():
            tier1 = addr in prologue_backed
            tier2 = (
                origins & _TRUSTED_ORIGINS
                and addr not in interior
                and not any(lo < addr < hi for lo, hi in shadowed)
            )
            if tier1 or tier2:
                confirmed[addr] = origins
            else:
                self.rejected += 1

        ceilings = self._ceilings(sorted(confirmed))
        starts = sorted(confirmed)

        # Cut, learn which functions never return, cut again knowing it. A call
        # to `abort`, `_xt_panic` or `esp_system_abort` is followed in the byte
        # stream by whatever the linker put next, not by the caller's own code,
        # and treating that as fallthrough is how a 22-byte
        # `xt_unhandled_interrupt` swallowed 1,251 bytes of exception-handler
        # assembly. Iterated because the property is transitive: a function
        # whose every path ends in a call to a noreturn function is itself
        # noreturn, and each pass makes one more layer of that visible.
        noreturn: set[int] = set()
        functions: list[RecoveredFunction] = []
        for _pass in range(NORETURN_PASSES):
            functions = [
                fn
                for addr in starts
                if (fn := self._cut_one(addr, confirmed[addr], ceilings[addr], noreturn))
                is not None
            ]
            found = {f.entry for f in functions if f.never_returns}
            if found == noreturn:
                break
            noreturn = found
        self.noreturn = noreturn
        return functions

    def _ceilings(self, starts: list[int]) -> dict[int, int]:
        """Where each function must stop: the next entry, or the segment end.

        Xtensa code is dense — measured, consecutive functions are separated by
        0 to 3 bytes of alignment padding — so an edge leading past the next
        entry is a tail call or a shared cold block, never this function's body.
        """
        ceilings: dict[int, int] = {}
        for i, addr in enumerate(starts):
            span = self.exec_span(addr)
            limit = starts[i + 1] if i + 1 < len(starts) else None
            ceilings[addr] = min(
                x for x in (limit, span.end if span else None) if x is not None
            )
        return ceilings

    def _incomplete_spans(
        self, prologue_backed: dict[int, set[str]]
    ) -> list[tuple[int, int]]:
        """Spans of functions whose bodies cannot have been fully recovered.

        A `jx` is a switch dispatch nothing can follow statically, so the bytes
        of its arms are never decoded — and undecoded bytes that later get
        decoded from some arbitrary offset produce instructions that were never
        there, including calls to addresses that are not instruction boundaries
        at all. Anything landing inside one of these spans has to be treated as
        the shadow of that, not as a discovery.
        """
        starts = sorted(prologue_backed)
        ceilings = self._ceilings(starts)
        spans: list[tuple[int, int]] = []
        for addr in starts:
            fn = self._cut_one(addr, prologue_backed[addr], ceilings[addr], set())
            if fn is not None and any(
                i.cls is InsnClass.JUMP_INDIRECT for i in fn.instructions
            ):
                spans.append((fn.entry, fn.span_end))
        return spans

    def _literal_pools(self) -> tuple[list[int], dict[int, list[int]]]:
        """Every address an `l32r` loads from, and who loads it.

        This is what tells an unreachable *tail of code* apart from a literal
        pool, and the two must not be confused: the tail belongs to the function
        before it, the pool belongs to the function after it (Xtensa pools
        precede their user). Guessing from the bytes alone cannot separate them
        — a pool of small constants and a run of instructions look alike — but
        a pool is by definition the thing an `l32r` points at, and the descent
        has already resolved every `l32r` it reached.

        The referrers matter as much as the addresses: pools also sit *inside* a
        function, between its basic blocks, and one of those must not be read as
        the end of it. Which function's code loads from a pool is what separates
        the two cases.
        """
        refs: dict[int, list[int]] = {}
        for addr, insn in self.code.items():
            if insn.cls is InsnClass.LITERAL_LOAD and insn.target is not None:
                refs.setdefault(insn.target, []).append(addr)
        return sorted(refs), refs

    def _extent(
        self, entry: int, flow_end: int, ceiling: int, incomplete: bool
    ) -> int:
        """Where the function ends, past the last instruction flow reached.

        Control flow stops early in two common shapes — a `jx` switch table
        whose arms are unreachable statically, and a call to a function that
        never returns — leaving a tail of real code unclaimed. Measured on the
        three `printf` bodies, flow reached 535 of 11,325 bytes; taking the last
        reached instruction as the end would canonicalize a 5% fragment of the
        function under the whole function's identity, which is worse than
        useless: it matches nothing and reports the function as absent.

        So the extent runs to the next function's entry, minus (a) any literal
        pool sitting in between, which belongs to that next function, and (b)
        the linker's alignment padding, measured on this image to be zero bytes
        in every one of the 628 inter-function gaps that has any.

        `incomplete` is what earns the extension, and only a function whose own
        body says it is incomplete gets it — one holding a `jx` whose switch
        arms nothing can follow, or one with an edge into its own window that
        the descent never decoded. Unclaimed bytes after a function that ended
        cleanly on a `ret`, with every edge accounted for, are not its tail:
        they are code recovery missed, usually hand-written assembly reached
        from the vector table. Swallowing those was measured to turn 22-byte
        `xt_unhandled_interrupt` into a 1,273-byte function.
        """
        if flow_end >= ceiling or not incomplete:
            return flow_end
        stop = ceiling
        idx = bisect.bisect_left(self._pool_starts, flow_end)
        while idx < len(self._pool_starts) and self._pool_starts[idx] < ceiling:
            pool = self._pool_starts[idx]
            # A pool this function itself loads from is one of its own, sitting
            # between its blocks; the extent runs straight past it. So is a pool
            # nothing reads at all — in a body this incomplete, that only means
            # the `l32r` naming it sits in an arm flow never reached. Only a
            # pool read exclusively from outside the window belongs to someone
            # else, and it is the next function's.
            refs = self._pool_refs[pool]
            if refs and not any(entry <= r < ceiling for r in refs):
                stop = pool
                break
            idx += 1
        return max(flow_end, _strip_padding(self.exec_span(entry), flow_end, stop))

    def _cut_one(
        self, entry: int, origins: set[str], ceiling: int, noreturn: set[int]
    ) -> RecoveredFunction | None:
        """Everything reachable from `entry` without leaving [entry, ceiling)."""
        body: dict[int, Instruction] = {}
        leaders: set[int] = {entry}
        dangling = False
        stack = [entry]
        while stack:
            addr = stack.pop()
            if addr in body or not (entry <= addr < ceiling):
                continue
            insn = self.code.get(addr)
            if insn is None:
                # An edge into this function's own window with nothing decoded
                # at the far end. If the descent stopped there deliberately —
                # data, or the `ill` that padding decodes as — the body is
                # complete and simply ends. Otherwise it is a gap, and the one
                # conclusion that must not be drawn from a body with a gap in it
                # is that it never returns.
                dangling = dangling or addr not in self.blocked
                continue
            body[addr] = insn

            targets, falls_through = _successors(insn, noreturn)
            for target in targets:
                leaders.add(target)
                stack.append(target)
            if falls_through:
                nxt = addr + insn.size
                if insn.cls in (InsnClass.BRANCH, InsnClass.LOOP):
                    leaders.add(nxt)
                stack.append(nxt)

        if not body:
            return None

        ranges = _ranges_of(body)
        flow_end = max(a + i.size for a, i in body.items())
        # Whether this body is complete on its own terms. An indirect *jump* is
        # a switch dispatch whose arms live in this function and cannot be
        # followed; a dangling edge is a target inside the window the descent
        # never decoded. Either way there are bytes that belong here and were
        # not read, which is what licenses claiming the extent up to the next
        # function. An indirect *call* is not such a case — it leaves and comes
        # back, so it explains nothing, and gating on it was measured to extend
        # 22-byte `xt_unhandled_interrupt` (one `callx8`, then `retw.n`) across
        # 1,251 bytes of neighbouring assembly.
        jump_table = any(i.cls is InsnClass.JUMP_INDIRECT for i in body.values())
        incomplete = jump_table or dangling
        span_end = self._extent(entry, flow_end, ceiling, incomplete)
        if span_end > flow_end:
            ranges[-1] = (ranges[-1][0], span_end)
        callees = sorted(
            {
                i.target
                for i in body.values()
                if i.cls is InsnClass.CALL and i.target is not None
            }
        )
        indirect = sum(
            1
            for i in body.values()
            if i.cls in (InsnClass.CALL_INDIRECT, InsnClass.JUMP_INDIRECT)
        )
        edges = sum(
            len(_successors(i, noreturn)[0]) + (1 if _successors(i, noreturn)[1] else 0)
            for i in body.values()
            if i.cls
            in (
                InsnClass.BRANCH,
                InsnClass.LOOP,
                InsnClass.JUMP,
                InsnClass.JUMP_INDIRECT,
                InsnClass.RETURN,
            )
        )

        insns = [body[a] for a in sorted(body)]
        return RecoveredFunction(
            entry=entry,
            size=span_end - entry,
            ranges=ranges,
            span_end=span_end,
            origins=sorted(origins),
            is_thunk=len(body) == 1 and insns[0].cls is InsnClass.JUMP,
            never_returns=(
                not any(i.cls is InsnClass.RETURN for i in body.values())
                and not incomplete
            ),
            basic_blocks=len(leaders & set(body)),
            edges=edges,
            indirect_calls=indirect,
            callees=callees,
            instructions=insns,
        )

def _strip_padding(span: Span | None, floor: int, stop: int) -> int:
    """Walk `stop` back over the linker's inter-function alignment padding.

    Measured on this image: all 628 non-empty gaps between consecutive function
    symbols are zero bytes, and a symbol's `st_size` excludes them. Never walks
    below `floor`, so a function whose own last instruction ends in a zero byte
    keeps it.
    """
    if span is None:
        return stop
    while stop > floor and span.slice_at(stop - 1, 1) == b"\x00":
        stop -= 1
    return stop


def _is_windowed_prologue(insn: Instruction) -> bool:
    """Whether `insn` is a real `entry`, not a byte pattern that decodes as one.

    `entry` allocates the callee's stack frame, so its first operand is always
    the stack pointer — a compiler has no reason to emit it on any other
    register, and the ABI gives it none. Measured over this image: all 883 true
    prologues are `entry a1, N`; all 18 addresses where a scan hit decoded as
    `entry` on some other register (a11, a4, a12) were interior bytes of the
    three large `printf` bodies, whose jump tables leave them unreachable and
    therefore undecoded, so nothing else contradicted them.
    """
    return (
        insn.cls is InsnClass.ENTRY
        and bool(insn.operands)
        and insn.operands[0].strip().lower() == "a1"
    )


def _successors(insn: Instruction, noreturn: frozenset[int] | set[int] = frozenset()) -> tuple[list[int], bool]:
    """Intra-procedural CFG edges: (explicit targets, falls through).

    A `call` falls through — control comes back — unless the callee is known
    not to return. A `loop` falls through into its body *and* targets the loop
    end. `jx`/`callx` targets are unknowable statically and are counted, never
    guessed.
    """
    if insn.cls in (InsnClass.RETURN, InsnClass.JUMP_INDIRECT, InsnClass.DATA):
        return [], False
    if insn.mnemonic in HARD_STOP:
        return [], False
    if insn.cls is InsnClass.CALL and insn.target in noreturn:
        return [], False
    if insn.cls is InsnClass.JUMP:
        return ([insn.target] if insn.target is not None else []), False
    if insn.cls in (InsnClass.BRANCH, InsnClass.LOOP):
        return ([insn.target] if insn.target is not None else []), True
    return [], True


def _ranges_of(body: dict[int, Instruction]) -> list[tuple[int, int]]:
    """Maximal contiguous [start, end) runs covered by the body's instructions."""
    ranges: list[tuple[int, int]] = []
    for addr in sorted(body):
        end = addr + body[addr].size
        if ranges and ranges[-1][1] == addr:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((addr, end))
    return ranges
