"""Dependency-free command-line interface for espfw's focused tool surface."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from espfw import __version__, provenance
from espfw.errors import EspfwError
from espfw.schema import to_data


@dataclass(slots=True)
class Ctx:
    json: bool = False
    cache_dir: Path | None = None
    output: Path | None = None


def _add_common(parser: argparse.ArgumentParser, *, defaults: bool = False) -> None:
    default = None if defaults else argparse.SUPPRESS
    parser.add_argument(
        "--json",
        action="store_true",
        default=False if defaults else argparse.SUPPRESS,
        help="emit machine-readable JSON",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default,
        help="override the corpus/cache location",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=default,
        help="write complete JSON output to this file",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="espfw",
        description="Inspect ESP32 firmware, create mapped ELFs, and match corpus symbols.",
    )
    _add_common(parser, defaults=True)
    parser.add_argument("--version", action="version", version=f"espfw {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    flash = commands.add_parser(
        "flash-info", help="print structure and metadata from a flash dump or app image"
    )
    _add_common(flash)
    flash.add_argument("image", type=Path)
    flash.add_argument("--slot", help="application partition label to inspect")
    flash.set_defaults(handler=_flash_info)

    elf = commands.add_parser("elf", help="write a Ghidra-loadable ELF")
    _add_common(elf)
    elf.add_argument("image", type=Path)
    elf.add_argument("out", type=Path)
    elf.add_argument("--slot", help="application partition label to export")
    elf.set_defaults(handler=_elf)

    symbols = commands.add_parser(
        "symbols", help="match functions against every current corpus build"
    )
    _add_common(symbols)
    symbols.add_argument("image", type=Path)
    symbols.add_argument("--slot", help="application partition label to inspect")
    symbols.set_defaults(handler=_symbols)

    corpus = commands.add_parser("corpus", help="manage the SQLite signature corpus")
    _add_common(corpus)
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)

    build = corpus_commands.add_parser("build", help="build or import one corpus entry")
    _add_common(build)
    build.add_argument("--version", required=True, help="ESP-IDF version, for example v5.4")
    build.add_argument("--config", default="default", help="preset or sdkconfig path")
    build.add_argument("--chip", default="esp32")
    build.add_argument("--jobs", "-j", type=int, default=0)
    build.add_argument("--from-artifacts", type=Path)
    build.add_argument("--show-build", action="store_true")
    build.set_defaults(handler=_corpus_build)

    listing = corpus_commands.add_parser("list", help="list cached corpus builds")
    _add_common(listing)
    listing.add_argument("--version")
    listing.set_defaults(handler=_corpus_list)

    arduino = corpus_commands.add_parser(
        "build-arduino", help="build Arduino core signatures"
    )
    _add_common(arduino)
    arduino.add_argument("--core", default="")
    arduino.add_argument("--chip", default="esp32")
    arduino.add_argument("--popular", action="store_true")
    arduino.add_argument("--rebuild-image", action="store_true")
    arduino.add_argument("--show-build", action="store_true")
    arduino.set_defaults(handler=_corpus_build_arduino)

    remove = corpus_commands.add_parser("rm", help="remove one cached corpus build")
    _add_common(remove)
    remove.add_argument("--version", required=True)
    remove.add_argument("--config-hash")
    remove.add_argument("--chip", default="esp32")
    remove.add_argument("--yes", action="store_true")
    remove.set_defaults(handler=_corpus_rm)

    gc = corpus_commands.add_parser("gc", help="remove stale corpus data")
    _add_common(gc)
    gc.add_argument("--dry-run", action="store_true")
    gc.set_defaults(handler=_corpus_gc)
    return parser


def _state(args: argparse.Namespace) -> Ctx:
    return Ctx(
        json=getattr(args, "json", False),
        cache_dir=getattr(args, "cache_dir", None),
        output=getattr(args, "output", None),
    )


def _emit(
    state: Ctx,
    command: str,
    result: Any,
    render: Callable[[Any], None],
) -> None:
    warnings = list(getattr(result, "warnings", []) or [])
    result_provenance = getattr(result, "provenance", None) or provenance.current()
    payload = {
        "command": command,
        "provenance": to_data(result_provenance),
        "warnings": warnings,
        "result": to_data(result),
    }
    if state.output is not None:
        text = json.dumps(payload, indent=2)
        state.output.write_text(text)
        print(f"espfw {command}: JSON written to {state.output} ({len(text):,} bytes)")
    elif state.json:
        print(json.dumps(payload, separators=(",", ":")))
    else:
        render(result)


def _flash_info(args: argparse.Namespace) -> None:
    from espfw.parse import parse_file

    result = parse_file(args.image, select_slot=args.slot)
    _emit(_state(args), "flash-info", result, _render_flash_info)


def _elf(args: argparse.Namespace) -> None:
    from espfw.elfexport import build_analysis_elf

    result = build_analysis_elf(args.image, args.out, slot=args.slot)
    _emit(_state(args), "elf", result, _render_elf)


def _symbols(args: argparse.Namespace) -> None:
    from espfw.symbols.run import run_symbols

    result = run_symbols(args.image, slot=args.slot, cache_dir=_state(args).cache_dir)
    _emit(_state(args), "symbols", result, _render_symbols)


def _corpus_build(args: argparse.Namespace) -> None:
    from espfw.corpus.build import build_corpus, harvest_artifacts

    state = _state(args)
    if args.from_artifacts:
        result = harvest_artifacts(
            args.from_artifacts,
            version=args.version,
            chip=args.chip,
            config_name=args.config,
            cache_dir=state.cache_dir,
        )
    else:
        result = build_corpus(
            version=args.version,
            config=args.config,
            chip=args.chip,
            jobs=args.jobs,
            cache_dir=state.cache_dir,
            verbose=args.show_build,
        )
    _emit(state, "corpus build", result, _render_corpus_build)


def _corpus_list(args: argparse.Namespace) -> None:
    from espfw.corpus.store import open_store

    state = _state(args)
    with open_store(state.cache_dir) as store:
        result = store.list_builds(version=args.version)
    _emit(state, "corpus list", result, _render_corpus_list)


def _corpus_build_arduino(args: argparse.Namespace) -> None:
    from espfw.corpus.arduino import FQBN_CONFIGS, POPULAR_CORES, build_arduino_corpus

    cores = list(POPULAR_CORES) if args.popular else ([args.core] if args.core else [])
    if not cores:
        raise EspfwError(
            "give --core <version> or --popular",
            remedy="Popular cores: " + ", ".join(POPULAR_CORES),
        )
    state = _state(args)
    results = [
        build_arduino_corpus(
            core_version=core,
            chip=args.chip,
            config_name=config,
            cache_dir=state.cache_dir,
            verbose=args.show_build,
            rebuild_image=args.rebuild_image,
        )
        for core in cores
        for config in FQBN_CONFIGS
    ]
    _emit(state, "corpus build-arduino", results, _render_corpus_build_many)


def _corpus_rm(args: argparse.Namespace) -> None:
    from espfw.corpus.store import open_store

    state = _state(args)
    with open_store(state.cache_dir) as store:
        matches = [
            build
            for build in store.builds_for(args.version, args.chip)
            if not args.config_hash or build.key.config_hash.startswith(args.config_hash)
        ]
        if not matches:
            raise EspfwError(
                f"no cached build for {args.version}/{args.chip}"
                + (f" with config hash {args.config_hash}" if args.config_hash else ""),
                remedy="`espfw corpus list` shows what is cached.",
            )
        if len(matches) > 1:
            options = "\n".join(
                f"  {item.config_name:20s} {item.key.config_hash[:12]}"
                for item in matches
            )
            raise EspfwError(
                f"{len(matches)} builds match {args.version}/{args.chip}",
                remedy=f"Narrow the selection with --config-hash:\n{options}",
            )
        target = matches[0]
        removed = 0
        if args.yes:
            removed = store.remove_build(target.id)
            store.commit()

    result = {
        "removed": bool(args.yes),
        "functions": removed if args.yes else target.function_count,
        "source": to_data(target.as_source()),
    }
    _emit(state, "corpus rm", result, _render_corpus_rm)


def _corpus_gc(args: argparse.Namespace) -> None:
    from espfw.corpus.store import open_store

    state = _state(args)
    with open_store(state.cache_dir) as store:
        result = store.gc(dry_run=args.dry_run)
    _emit(state, "corpus gc", result, _render_corpus_gc)


def _warnings(result: Any) -> None:
    for warning in getattr(result, "warnings", []) or []:
        print(f"warning: {warning}", file=sys.stderr)


def _render_flash_info(result: Any) -> None:
    print(f"{result.path}  {result.size:,} bytes  sha256:{result.sha256[:16]}...")
    print(f"input kind : {result.input_kind}")
    print(f"chip       : {result.chip or 'unknown'}")
    if result.flash_base_offset:
        print(f"flash base : 0x{result.flash_base_offset:x}")
    if result.partition_table_offset is not None:
        print(f"partition table: 0x{result.partition_table_offset:x}")
        for part in result.partitions:
            flags = " encrypted" if part.encrypted else ""
            present = "" if part.present_in_file else " not-in-dump"
            print(
                f"  0x{part.offset:06x}  0x{part.size:06x}  "
                f"{part.type_name}/{part.subtype_name}  {part.label}{flags}{present}"
            )
    for index, image in enumerate(result.images):
        selected = " selected" if index == result.selected_image else ""
        label = f" {image.partition_label}" if image.partition_label else ""
        print(
            f"{image.role}{label}: offset 0x{image.file_offset:x}, "
            f"entry 0x{image.header.entry_addr:08x}, {image.image_len:,} bytes{selected}"
        )
        if image.app_desc:
            desc = image.app_desc
            print(
                f"  app: {desc.project_name} {desc.version}, IDF {desc.idf_ver}, "
                f"built {desc.date} {desc.time}"
            )
        for segment in image.segments:
            kind = "code" if segment.executable else "data"
            print(
                f"  0x{segment.load_addr:08x}  {segment.length:8,d}  {kind:4s}  "
                f"{segment.region or 'unmapped'}  image+0x{segment.file_offset:x}"
            )
    _warnings(result)


def _render_elf(result: Any) -> None:
    print(f"{result.path}  {result.bytes_written:,} bytes  chip {result.chip or 'unknown'}")
    print(f"entry      : 0x{result.entry:08x}")
    for section in result.sections:
        kind = "code" if section.executable else "data"
        print(
            f"  0x{section.vaddr:08x}  {section.size:8,d}  {kind:4s}  "
            f"{section.name}  source+0x{section.file_offset:x}"
        )
    _warnings(result)


def _render_symbols(result: Any) -> None:
    coverage = result.coverage
    versions = sorted({source.idf_version for source in result.corpus_sources})
    sources_by_id = {source.build_id: source for source in result.corpus_sources}
    print(f"{result.path}  chip {result.chip}")
    print(
        f"corpus     : {len(result.corpus_sources):,} build(s), "
        f"{len(versions):,} version(s)"
    )
    print(
        f"matched    : {coverage.matched:,} of {coverage.total:,} functions "
        f"({coverage.ratio:.1%})"
    )
    if result.identified:
        print("\nELF ADDRESS  IMAGE OFFSET  SIZE   SYMBOL  CORPUS SOURCE(S)")
    for function in result.identified:
        offset = f"0x{function.offset:08x}" if function.offset is not None else "-"
        sources = [
            f"{build_id}:{sources_by_id[build_id].idf_version}/"
            f"{sources_by_id[build_id].config_name}"
            for build_id in function.corpus_source_ids
            if build_id in sources_by_id
        ]
        source_text = ", ".join(sources) or "unknown"
        ambiguity = (
            f" (+{len(function.ambiguous_with)} ambiguous name(s))"
            if function.ambiguous_with
            else ""
        )
        print(
            f"0x{function.vaddr:08x}  {offset:12s}  {function.size:5d}  "
            f"{function.name}{ambiguity}  {source_text}"
        )
    _render_symbol_hit_stats(result, sources_by_id)
    _render_layout(result)
    _render_unidentified(result)
    _warnings(result)


def _render_layout(result: Any, width: int = 64) -> None:
    """One bar per code segment, plus the regions no component claims.

    Code is laid out in link order, so each component occupies a run of
    addresses. The bar paints each character by what most of its span is:
    exact matches, neighbours of exact matches, or nothing the corpus knows.
    The last kind, listed below the bars, is where the application is.
    """
    if not result.layout or not result.segments:
        return
    print("\nlayout: █ identified  ▒ inferred from neighbours  · unidentified")
    for seg in sorted(result.segments, key=lambda s: s.start):
        end = seg.start + seg.size
        regions = [r for r in result.layout if r.end > seg.start and r.start < end]
        if not regions:
            continue
        cells = []
        step = seg.size / width
        for i in range(width):
            lo, hi = seg.start + i * step, seg.start + (i + 1) * step
            weight = {"█": 0.0, "▒": 0.0, "·": 0.0}
            for r in regions:
                overlap = min(hi, r.end) - max(lo, r.start)
                if overlap <= 0:
                    continue
                if r.component is None:
                    weight["·"] += overlap
                else:
                    share = r.identified / r.functions if r.functions else 1.0
                    weight["█"] += overlap * share
                    weight["▒"] += overlap * (1 - share)
            cells.append(max(weight, key=weight.get) if any(weight.values()) else " ")
        print(f"  {seg.name:<10s} 0x{seg.start:08x}  {''.join(cells)}  {seg.size:,} bytes")

    unclaimed = sorted(
        (r for r in result.layout if r.component is None and r.bytes >= 2048),
        key=lambda r: -r.bytes,
    )
    if unclaimed:
        print("\nregions no component claims (>= 2 KB), largest first:")
        print("  START       END         BYTES    FUNCS  BETWEEN")
        ordered = result.layout
        for r in unclaimed[:12]:
            i = ordered.index(r)
            before = next((x.component for x in reversed(ordered[:i]) if x.component), "-")
            after = next((x.component for x in ordered[i + 1 :] if x.component), "-")
            print(
                f"  0x{r.start:08x}  0x{r.end:08x}  {r.bytes:7,}  {r.functions:5,}  "
                f"{before} | {after}"
            )


def _render_unidentified(result: Any, limit: int = 20) -> None:
    """The functions the corpus could not name — the part worth reading.

    Everything identified is SDK code somebody else wrote and published; what
    is left is the application, or SDK code from a version the corpus lacks.
    LIKELY separates the two: the component whose matches sit on both sides
    of the function in memory, or "-" when it sits in a region nothing claims.
    """
    functions = result.unidentified
    if not functions:
        return
    total_bytes = sum(f.size for f in functions)
    print(
        f"\nunidentified: {len(functions):,} function(s), {total_bytes:,} bytes "
        f"— largest first"
    )
    print("ELF ADDRESS  IMAGE OFFSET  SIZE    IN  LIKELY           CALLS KNOWN SDK FUNCTIONS")
    for function in functions[:limit]:
        offset = f"0x{function.offset:08x}" if function.offset is not None else "-"
        calls = ", ".join(function.calls_known[:4])
        if len(function.calls_known) > 4:
            calls += f", +{len(function.calls_known) - 4}"
        likely = (function.likely_component or "-")[:15]
        print(
            f"0x{function.vaddr:08x}  {offset:12s}  {function.size:6,}  "
            f"{function.in_degree:3d}  {likely:<15s}  {calls or '-'}"
        )
    if len(functions) > limit:
        print(f"... {len(functions) - limit:,} more in --json")


def _render_symbol_hit_stats(result: Any, sources_by_id: dict[int, Any]) -> None:
    matched = result.coverage.matched
    if not matched:
        return
    functions = result.identified
    ambiguous = sum(1 for function in functions if function.ambiguous_with)
    print(f"\ncorpus hits: {matched:,} identified function(s)")
    print(
        f"  ambiguity: {matched - ambiguous:,} unambiguous "
        f"({(matched - ambiguous) / matched:.1%}), "
        f"{ambiguous:,} ambiguous ({ambiguous / matched:.1%})"
    )

    if result.coverage.by_component:
        print("  by component:")
        _print_ranked(
            [(name, count) for name, count in result.coverage.by_component.items()],
            total=matched,
            limit=12,
            unit="component",
        )

    # Per version and per build: how many identified functions each one
    # supplied. A function found in several builds counts once for each, so
    # the columns do not sum to `matched`.
    by_version: Counter[str] = Counter()
    by_build: Counter[int] = Counter()
    for function in functions:
        ids = [b for b in function.corpus_source_ids if b in sources_by_id]
        by_build.update(ids)
        by_version.update({sources_by_id[b].idf_version for b in ids})

    if by_version:
        print(f"  by version ({len(by_version)} of "
              f"{len({s.idf_version for s in result.corpus_sources})} contributed):")
        _print_ranked(by_version.most_common(), total=matched, limit=10, unit="version")
    if by_build:
        print(f"  by corpus source ({len(by_build)} of "
              f"{len(result.corpus_sources)} searched build(s) contributed):")
        rows = [
            (f"{b}:{sources_by_id[b].idf_version}/{sources_by_id[b].config_name}", n)
            for b, n in by_build.most_common()
        ]
        _print_ranked(rows, total=matched, limit=12, unit="build")


def _print_ranked(
    rows: list[tuple[str, int]], *, total: int, limit: int, unit: str
) -> None:
    """Print (label, count) rows with a share column, folding the tail."""
    rows = sorted(rows, key=lambda kv: (-kv[1], kv[0]))
    top, rest = rows[:limit], rows[limit:]
    if rest:
        top.append((f"other ({len(rest)} {unit}(s))", sum(n for _, n in rest)))
    width = max(len(label) for label, _ in top)
    for label, count in top:
        print(f"    {label:<{width}}  {count:>8,}  {count / total:>6.1%}")


def _render_corpus_build(result: Any) -> None:
    print(f"corpus build complete in {result.duration_seconds:.0f}s")
    print(f"key        : {result.key.describe()}")
    print(f"config     : {result.config_name}")
    print(f"signatures : {result.functions_stored:,}")
    _warnings(result)


def _render_corpus_build_many(results: list[Any]) -> None:
    for index, result in enumerate(results):
        if index:
            print()
        _render_corpus_build(result)


def _render_corpus_list(result: Any) -> None:
    print(f"{result.db_path}  canonicalizer v{result.canon_version}")
    for build in result.builds:
        stale = " stale" if build.stale else ""
        print(
            f"{build.key.idf_version:24s} {build.key.chip:8s} "
            f"{build.config_name:16s} {build.key.config_hash[:12]} "
            f"{build.function_count:8,d}  {build.key.toolchain}{stale}"
        )
    _warnings(result)


def _render_corpus_rm(result: dict[str, Any]) -> None:
    action = "removed" if result["removed"] else "would remove"
    source = result["source"]
    print(
        f"{action} {source['idf_version']}/{source['chip']} "
        f"{source['config_name']} ({source['config_hash'][:12]}), "
        f"{result['functions']:,} signatures"
    )
    if not result["removed"]:
        print("re-run with --yes to remove it")


def _render_corpus_gc(result: Any) -> None:
    action = "would remove" if result.dry_run else "removed"
    print(
        f"{action} {len(result.stale_builds):,} stale build(s), "
        f"{result.functions_removed:,} function signatures"
    )
    _warnings(result)


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        args.handler(args)
    except EspfwError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.remedy:
            print(exc.remedy, file=sys.stderr)
        raise SystemExit(exc.exit_code) from exc


if __name__ == "__main__":
    main()
