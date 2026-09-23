"""Score boundary recovery against a mask ROM's own symbols.

The hardest case there is, and the reason it is worth standing on: a ROM image
has no entry point to start from, no relocation, no `esp_app_desc_t`, and its
hand-written assembly does not follow the compiler's conventions. Everything the
descent has to work with is the code itself. Whatever recall holds here is a
floor for what firmware gets.

The ROM ELF ships with a full symbol table, so this mints its own ground truth:

    uv run python scripts/measure_rom_boundaries.py            # esp32 rev0
    uv run python scripts/measure_rom_boundaries.py esp32s3

Two tiers of truth, because they answer different questions: symbols with a size
score entry points *and* extents; the zero-size ones (assembly stubs, vector
entries) are real entry points the ELF states no extent for, and scoring them as
extent failures would be measuring the ELF, not the tool.
"""

from __future__ import annotations

import sys

from espfw import elfreader
from espfw.boundaries import native
from espfw.soc import rom


def main(chip: str = "esp32", revision: int = 0) -> int:
    paths = rom.available()
    path = paths.get((chip, revision))
    if path is None:
        have = ", ".join(f"{c} rev{r}" for c, r in sorted(paths)) or "none"
        print(f"no ROM ELF for {chip} rev{revision}; found: {have}")
        print("Install esp-rom-elfs via the IDF tools installer, or set "
              "ESPFW_ROM_ELFS.")
        return 2

    elf = elfreader.load(path)
    spans = [
        native.Span(
            load_addr=sec.addr,
            data=sec.data(),
            region=sec.name,
            executable=sec.is_code,
        )
        for sec in elf.sections
        if sec.is_alloc and sec.addr and sec.data()
    ]
    code_bytes = sum(len(s.data) for s in spans if s.executable)

    truth: dict[int, int] = {}
    for sym in elf.symbols():
        if sym.is_func and any(
            s.executable and s.contains(sym.value) for s in spans
        ):
            truth[sym.value] = max(truth.get(sym.value, 0), sym.size)
    sized = {a: n for a, n in truth.items() if n > 0}

    # No entry address: a ROM has none, and passing one would flatter the result.
    result = native.recover(chip, spans, entry_addr=None)
    found = {f.entry: f for f in result.functions}

    hits = set(truth) & set(found)
    extent_hits = set(sized) & set(found)
    exact = sum(1 for a in extent_hits if found[a].span_end - a == sized[a])
    claimed = sum(f.size for f in result.functions)

    print(f"{path.name}   {code_bytes:,} executable bytes")
    print(f"  truth        {len(truth):,} entry points ({len(sized):,} sized)")
    print(f"  recovered    {len(found):,}")
    print(f"  recall       {len(hits) / len(truth):.1%}")
    print(f"  precision    {len(hits) / len(found):.1%}")
    if extent_hits:
        print(f"  extent exact {exact / len(extent_hits):.1%} "
              f"(over {len(extent_hits):,} sized)")
    print(f"  coverage     {claimed / code_bytes:.1%} of executable bytes")
    print(f"  seeds        {result.seeds_by_origin}  rejected "
          f"{result.seeds_rejected:,}")

    by_conf: dict[str, int] = {}
    for fn in result.functions:
        for origin in fn.origins:
            by_conf[origin] = by_conf.get(origin, 0) + 1
    print(f"  origins kept {by_conf}")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    sys.exit(main(*(args[:1] or ["esp32"]), *(int(a) for a in args[1:2])))
