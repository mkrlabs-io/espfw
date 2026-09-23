"""Function recovery and exact all-corpus lookup for `espfw symbols`."""

from __future__ import annotations

import hashlib
from pathlib import Path

from espfw import provenance
from espfw.corpus.store import open_store
from espfw.disasm.toolchain import find_objdump, objdump_version
from espfw.errors import CorpusMissingError
from espfw.match import ExactMatcher, Query, Signature
from espfw.pipeline import analyze_image
from espfw.symbols.models import (
    CodeSegment,
    Coverage,
    IdentifiedFunction,
    Region,
    SymbolsResult,
    UnidentifiedFunction,
)


def run_symbols(
    image_path: str | Path,
    slot: str | None = None,
    cache_dir: Path | None = None,
    analysis=None,
) -> SymbolsResult:
    """Exact-match one image against every current corpus build for its chip."""
    if analysis is None:
        analysis = analyze_image(image_path, slot=slot, cache_dir=cache_dir)
    parsed, chip, functions = analysis.parsed, analysis.chip, analysis.functions

    warnings: list[str] = [
        *list(getattr(parsed, "warnings", []) or []),
        *list(functions.warnings),
    ]

    with open_store(cache_dir) as store:
        records = store.current_builds(chip)
        if not records:
            raise CorpusMissingError(
                f"no current corpus data for {chip}",
                remedy="Populate it with `espfw corpus build --version <v> "
                f"--chip {chip} --config default`, or import an existing build "
                "with --from-artifacts. Corpus generation is never implicit.",
            )
        source_by_id = {item.id: item.as_source() for item in records}
        flat_rows = store.signatures_for_digests(
            chip, {form.digest for form in analysis.forms.values()}
        )
        signatures = [
            _signature(row, source_by_id[row["build_id"]]) for row in flat_rows
        ]

    matcher = ExactMatcher(signatures)

    forms = analysis.forms
    queries = [
        Query(key=str(entry), digest=form.digest) for entry, form in forms.items()
    ]
    hits = matcher.match(queries)

    entries = {fn.entry for fn in functions.functions}
    out_edges: dict[int, list[int]] = {}
    in_degree: dict[int, int] = dict.fromkeys(entries, 0)
    for entry, form in forms.items():
        targets = [t for t in form.call_targets if t in entries]
        out_edges[entry] = targets
        for t in targets:
            in_degree[t] = in_degree.get(t, 0) + 1

    identified: list[IdentifiedFunction] = []
    unidentified: list[UnidentifiedFunction] = []
    by_component: dict[str, int] = {}

    for fn in functions.functions:
        hit = hits.get(str(fn.entry))
        if hit:
            identified.append(
                IdentifiedFunction(
                    offset=fn.file_offset,
                    vaddr=fn.entry,
                    size=fn.size,
                    name=hit.name,
                    component=hit.component,
                    confidence=hit.confidence,
                    origin=hit.origin,
                    ambiguous_with=hit.ambiguous_with,
                    shared_components=hit.shared_components,
                    boundary_confidence=str(fn.confidence),
                    corpus_source_ids=_corpus_source_ids(hit.name, hit.signatures),
                )
            )
            comp = hit.component or "(unattributed)"
            by_component[comp] = by_component.get(comp, 0) + 1
        else:
            known = [
                hits[str(t)].name
                for t in out_edges.get(fn.entry, [])
                if str(t) in hits
            ]
            unidentified.append(
                UnidentifiedFunction(
                    offset=fn.file_offset,
                    vaddr=fn.entry,
                    size=fn.size,
                    in_degree=in_degree.get(fn.entry, 0),
                    out_degree=len(out_edges.get(fn.entry, [])),
                    calls_known=sorted(set(known)),
                    boundary_confidence=str(fn.confidence),
                )
            )

    layout = _layout(identified, unidentified)
    unidentified.sort(key=lambda u: (-u.size, -u.in_degree))
    identified.sort(key=lambda i: i.vaddr)
    segments = [
        CodeSegment(name=name, start=start, size=size)
        for name, start, size in analysis.code_segments
    ]

    total = len(functions.functions)
    coverage = Coverage(
        matched=len(identified),
        total=total,
        ratio=round(len(identified) / total, 4) if total else 0.0,
        by_component=dict(sorted(by_component.items(), key=lambda kv: -kv[1])),
    )

    _coverage_warnings(coverage, functions, warnings)

    return SymbolsResult(
        path=parsed.path,
        chip=chip,
        corpus_sources=[item.as_source() for item in records],
        identified=identified,
        unidentified=unidentified,
        coverage=coverage,
        segments=segments,
        layout=layout,
        warnings=warnings,
        provenance=provenance.current(
            objdump_version=objdump_version(str(find_objdump(chip))),
            corpus_revision=_corpus_revision(records),
        ),
    )


# Smallest exact match allowed to label its neighbours. A 13-byte function is
# "load a global, return", and its canonical form is shared with every other
# such getter in the image -- including the application's, which the corpus
# has never seen, so the ambiguity check cannot flag it. Measured on the
# ESP-Hosted firmware, tiny anchors planted four separate "lwip" regions, two
# of them inside the application; at 24 bytes lwip is one region again and the
# number of components split across non-adjacent regions drops 27 -> 19, for
# 12% fewer labelled functions. A missing label is recoverable; application
# code absorbed under an SDK label is not.
_ANCHOR_MIN_BYTES = 24


def _layout(
    identified: list[IdentifiedFunction], unidentified: list[UnidentifiedFunction]
) -> list[Region]:
    """Cut the address space into component runs, and label the gaps.

    Only unambiguous matches of at least `_ANCHOR_MIN_BYTES` anchor a run: an
    ambiguous name is one of several components' functions with identical
    code, and letting it label its neighbours put Arduino components into a
    pure ESP-IDF image. Measured on the ESP-Hosted firmware, dropping ambiguous
    anchors took 644 fragmented runs down to 153 and raised the share of
    functions inside a labelled run from 42% (exact matches alone) to 67%.
    """

    def anchor(f: IdentifiedFunction) -> str | None:
        # A function two components both carry cannot say which one is here,
        # so it must not label its neighbours as either.
        if f.ambiguous_with or f.shared_components or f.size < _ANCHOR_MIN_BYTES:
            return None
        return f.component or "(unattributed)"

    anchored: list[tuple[int, int, str | None, object]] = [
        (f.vaddr, f.size, anchor(f), f) for f in identified
    ] + [(u.vaddr, u.size, None, u) for u in unidentified]
    anchored.sort(key=lambda t: t[0])

    runs: list[Region] = []
    members: list[list[object]] = []
    for vaddr, size, component, fn in anchored:
        if runs and runs[-1].component == component:
            runs[-1].end = vaddr + size
            runs[-1].functions += 1
            members[-1].append(fn)
        else:
            runs.append(Region(start=vaddr, end=vaddr + size, component=component, functions=1))
            members.append([fn])

    # An unlabelled run between two runs of the same component is that
    # component: the linker put it there.
    merged: list[Region] = []
    merged_members: list[list[object]] = []
    for run, fns in zip(runs, members, strict=True):
        if (
            run.component is not None
            and len(merged) >= 2
            and merged[-1].component is None
            and merged[-2].component == run.component
        ):
            gap, gap_fns = merged.pop(), merged_members.pop()
            head, head_fns = merged.pop(), merged_members.pop()
            head.end = run.end
            head.functions += gap.functions + run.functions
            head.inferred += gap.functions
            merged.append(head)
            merged_members.append(head_fns + gap_fns + fns)
        else:
            merged.append(run)
            merged_members.append(list(fns))

    for region, fns in zip(merged, merged_members, strict=True):
        for fn in fns:
            if isinstance(fn, IdentifiedFunction):
                region.identified += 1
            elif region.component is not None:
                fn.likely_component = region.component
    return merged


def _signature(row, source) -> Signature:
    return Signature(
        name=row["name"],
        digest=row["digest"],
        component=row["component"],
        origin=row["origin"],
        source=source,
    )


def _corpus_source_ids(name: str, signatures: list[Signature]) -> list[int]:
    """Builds containing the selected name with this exact canonical form."""
    return sorted(
        {
            signature.source.build_id
            for signature in signatures
            if signature.name == name and signature.source is not None
        }
    )


def _corpus_revision(records) -> str:
    if len(records) == 1:
        record = records[0]
        return f"build:{record.id}@{record.created_at}"
    material = "\n".join(f"{r.id}@{r.created_at}" for r in records)
    digest = hashlib.sha256(material.encode()).hexdigest()[:16]
    return f"builds:{len(records)}@{digest}"


def _coverage_warnings(
    coverage: Coverage,
    functions,
    warnings: list[str],
) -> None:
    """Interpret the match rate honestly without guessing a version/config."""
    if not coverage.total:
        return

    if coverage.ratio < 0.5:
        boundary_ratio = functions.stats.coverage_ratio
        warnings.append(
            f"only {coverage.ratio:.0%} of recovered functions matched any current "
            "corpus build. The remainder can be vendor code, SDK code built with an "
            "uncached config/toolchain, or boundary-recovery misses (boundary "
            f"coverage was {boundary_ratio:.0%}). Exact matching also cannot see "
            "functions that differ by one instruction."
        )

    low = functions.stats.low_confidence
    if low and low / coverage.total > 0.1:
        warnings.append(
            f"{low:,} of {coverage.total:,} boundaries are low-confidence; those "
            "functions cannot match anything even if they are pure SDK, so they "
            "depress the match rate independently of the corpus"
        )
