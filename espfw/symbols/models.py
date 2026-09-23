"""Symbol lookup output schema."""

from __future__ import annotations

from espfw.corpus.models import CorpusSource
from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field, computed_field


def _hex(vaddr: int) -> str:
    """An address as hex, the form every other tool speaks.

    Emitted alongside the integer `vaddr` because a consumer -- almost always an
    agent cross-referencing Ghidra, objdump or a bookmark -- wants the hex
    identifier, and converting an int to hex in jq is genuinely painful and a
    measured source of failed queries. The int stays for sorting and arithmetic;
    this is the label.
    """
    return f"0x{vaddr:08x}"


class IdentifiedFunction(BaseModel):
    offset: int | None
    vaddr: int
    size: int
    name: str
    component: str | None = None
    confidence: float = 1.0
    origin: str = "archive"
    ambiguous_with: list[str] = Field(
        default_factory=list,
        description="Other corpus functions with the identical canonical form. "
        "Non-empty means the identity is a set of candidates, not a name.",
    )
    boundary_confidence: str = "medium"
    shared_components: list[str] = Field(
        default_factory=list,
        description="Other components in the same corpus build that carry this "
        "function byte for byte (mbedcrypto and tfpsacrypto both ship the mbedTLS "
        "wrappers). Non-empty means `component` is one of several equally valid "
        "attributions, not evidence that this component is linked.",
    )
    corpus_source_ids: list[int] = Field(
        default_factory=list,
        description="Build IDs containing the selected name and matching canonical "
        "form. Resolve them through SymbolsResult.corpus_sources.",
    )

    @computed_field
    @property
    def ambiguous_count(self) -> int:
        """How many names the identity really spans.

        Kept as a first-class field because human output reports the count rather
        than printing hundreds of equivalent short-function names inline.
        """
        return len(self.ambiguous_with)

    @computed_field
    @property
    def vaddr_hex(self) -> str:
        return _hex(self.vaddr)


class UnidentifiedFunction(BaseModel):
    offset: int | None
    vaddr: int
    size: int
    in_degree: int = 0
    out_degree: int = 0
    calls_known: list[str] = Field(
        default_factory=list,
        description="Identified SDK functions this one calls. Often enough "
        "context to guess its role without reading it.",
    )
    boundary_confidence: str = "medium"
    likely_component: str | None = Field(
        default=None,
        description="The component whose identified functions sit on both sides "
        "of this one in memory. The linker lays code out in link order, so this "
        "is very probably SDK code from that component that did not match "
        "exactly — not application code. Null means the function sits in a "
        "region no component claims.",
    )

    @computed_field
    @property
    def vaddr_hex(self) -> str:
        return _hex(self.vaddr)


class Region(BaseModel):
    """A contiguous run of functions in memory, labelled by component.

    Code is laid out in link order, so functions from one component are
    neighbours. A run is anchored by unambiguous exact matches; unmatched
    functions between two anchors of the same component are counted as
    `inferred`. A region with no component is the interesting kind: a stretch
    nothing in the corpus claims.
    """

    start: int
    end: int
    component: str | None = None
    functions: int = 0
    identified: int = 0
    inferred: int = 0

    @computed_field
    @property
    def start_hex(self) -> str:
        return _hex(self.start)

    @computed_field
    @property
    def bytes(self) -> int:
        return self.end - self.start


class CodeSegment(BaseModel):
    name: str
    start: int
    size: int


class Coverage(BaseModel):
    matched: int = 0
    total: int = 0
    ratio: float = 0.0
    by_component: dict[str, int] = Field(default_factory=dict)


class NearMissStatus(BaseModel):
    """Why modified-function detection did not run.

    An absent tier must not read as a clean-code verdict. All-corpus mode is
    exact-only, so this is reported rather than left implicit.
    """

    available: bool = False
    reason: str = (
        "All-corpus mode performs exact signature lookup only. Modified-function "
        "detection did not run; an empty result is NOT CHECKED, not "
        "'nothing was modified'."
    )


class SymbolsResult(BaseModel):
    path: str
    chip: str
    corpus_sources: list[CorpusSource] = Field(
        default_factory=list,
        description="Every current corpus build searched, whether or not it matched.",
    )
    identified: list[IdentifiedFunction] = Field(default_factory=list)
    unidentified: list[UnidentifiedFunction] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    segments: list[CodeSegment] = Field(
        default_factory=list, description="Executable segments, for the layout."
    )
    layout: list[Region] = Field(
        default_factory=list,
        description="Memory laid out as component runs, in address order.",
    )
    near_miss: NearMissStatus = Field(default_factory=NearMissStatus)
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None
