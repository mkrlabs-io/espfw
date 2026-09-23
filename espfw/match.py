"""Exact canonical-form matching: a dictionary lookup on the digest.

Ambiguity is preserved rather than resolved. Two corpus functions with the
same canonical form cannot be told apart by exact matching, so a hit reports
the preferred name *and* every other name sharing the form.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from espfw.corpus.models import CorpusSource


@dataclass(frozen=True, slots=True)
class Signature:
    """One corpus function, as the matcher sees it."""

    name: str
    digest: str
    component: str | None = None
    origin: str = "archive"
    """'archive' (pre-relaxation) or 'linked' (post-relaxation). Linker
    relaxation rewrites -mlongcalls call sequences, so the two origins are
    genuinely different code for the same source function."""
    source: CorpusSource | None = None


@dataclass(frozen=True, slots=True)
class Query:
    """One target function to identify."""

    key: str
    digest: str


@dataclass(slots=True)
class Hit:
    name: str
    confidence: float
    component: str | None = None
    origin: str = "archive"
    ambiguous_with: list[str] = field(default_factory=list)
    """Other corpus names sharing this canonical form. A non-empty list means
    the identity is a set, not a name, and must be reported as such."""
    shared_components: list[str] = field(default_factory=list)
    """Other components in the same build carrying this name with this form.
    IDF 5.5 ships the mbedTLS wrappers in both mbedcrypto and tfpsacrypto, and
    newlib's stubs in both newlib and the toolchain, so a match says nothing
    about which archive the image linked — and must not be read as evidence
    that the reported one is present."""
    signatures: list[Signature] = field(default_factory=list)
    """Every corpus signature with this form, retaining name-to-build provenance."""


class ExactMatcher:
    def __init__(self, signatures: list[Signature]) -> None:
        self._by_digest: dict[str, list[Signature]] = defaultdict(list)
        for sig in signatures:
            self._by_digest[sig.digest].append(sig)

    def match(self, queries: list[Query]) -> dict[str, Hit]:
        """Identify what can be identified. Unmatched queries are simply absent."""
        out: dict[str, Hit] = {}
        for q in queries:
            sigs = self._by_digest.get(q.digest)
            if not sigs:
                continue

            # Prefer the post-relaxation copy: firmware code has been through the
            # linker, so a 'linked' signature is the like-for-like reference.
            best = min(sigs, key=lambda s: (s.origin != "linked", s.name))
            names = sorted({s.name for s in sigs})
            ambiguous = [n for n in names if n != best.name]
            # Only within one build. The same function is filed under `soc` in
            # IDF 4.4 and `esp_hw_support` in 5.x; that is a rename, not two
            # archives both carrying it.
            per_build: dict[int, set[str]] = {}
            for s in sigs:
                if s.name == best.name and s.component and s.source:
                    per_build.setdefault(s.source.build_id, set()).add(s.component)
            components = sorted(
                {c for comps in per_build.values() if len(comps) > 1 for c in comps}
                - {best.component}
            )

            out[q.key] = Hit(
                name=best.name,
                # An exact canonical match is certain up to the canonicalizer's
                # masking; sharing a form with other names is the only way it can
                # be the wrong *name*, so that is what discounts it.
                confidence=1.0 if not ambiguous else 0.5,
                component=best.component,
                origin=best.origin,
                ambiguous_with=ambiguous,
                shared_components=components,
                signatures=sorted(
                    sigs,
                    key=lambda s: (
                        s.name,
                        s.origin != "linked",
                        s.source.build_id if s.source else -1,
                    ),
                ),
            )
        return out
