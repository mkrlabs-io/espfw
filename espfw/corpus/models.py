"""Schemas for the signature corpus."""

from __future__ import annotations

from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field


class BuildKey(BaseModel):
    """The corpus cache key.

    Toolchain is a first-class axis, not metadata: the same IDF version and the
    same sdkconfig built with a different toolchain produces wholesale codegen
    differences, which present as "the entire SDK is modified" if the corpus
    does not cover it.
    """

    idf_version: str
    config_hash: str
    chip: str
    toolchain: str

    def describe(self) -> str:
        return f"{self.idf_version} / {self.chip} / {self.config_hash[:12]} / {self.toolchain}"


class BuildRecord(BaseModel):
    id: int
    key: BuildKey
    config_name: str
    canon_version: int
    objdump_version: str | None = None
    created_at: str
    function_count: int = 0
    archive_functions: int = 0
    linked_functions: int = 0
    stale: bool = Field(
        default=False,
        description="True when canon_version differs from the running "
        "canonicalizer, so these signatures are not comparable with fresh ones.",
    )

    def as_source(self) -> CorpusSource:
        return CorpusSource(
            build_id=self.id,
            idf_version=self.key.idf_version,
            config_name=self.config_name,
            config_hash=self.key.config_hash,
            chip=self.key.chip,
            toolchain=self.key.toolchain,
            canon_version=self.canon_version,
            created_at=self.created_at,
        )


class CorpusSource(BaseModel):
    """One concrete corpus build that supplied or was searched for a signature."""

    build_id: int
    idf_version: str
    config_name: str
    config_hash: str
    chip: str
    toolchain: str
    canon_version: int
    created_at: str

    def describe(self) -> str:
        return (
            f"{self.idf_version}/{self.config_name}/"
            f"{self.config_hash[:12]}/{self.toolchain}"
        )


class CorpusListing(BaseModel):
    db_path: str
    builds: list[BuildRecord] = Field(default_factory=list)
    canon_version: int
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None


class GcResult(BaseModel):
    db_path: str
    dry_run: bool
    stale_builds: list[str] = Field(default_factory=list)
    functions_removed: int = 0
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None


class BuildResult(BaseModel):
    key: BuildKey
    config_name: str
    functions_stored: int = 0
    archive_functions: int = 0
    linked_functions: int = 0
    components: dict[str, int] = Field(default_factory=dict)
    duplicate_digests: int = Field(
        default=0,
        description="Distinct functions sharing one canonical form. These cannot "
        "be told apart by exact matching and are reported, not hidden.",
    )
    duration_seconds: float = 0.0
    docker_image: str | None = None
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None
