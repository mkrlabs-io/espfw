"""Schemas for `flash-info` output.

Load addresses are mandatory on every segment. Without them, l32r literal
pool resolution and call-target resolution are wrong, and canonicalization
degrades silently instead of failing loudly — so `Segment.load_addr` is a
required field with no default, and nothing downstream accepts a segment
lacking one.
"""

from __future__ import annotations

from enum import StrEnum

from espfw.models import Candidate, Evidence
from espfw.provenance import Provenance
from espfw.schema import BaseModel, Field


class InputKind(StrEnum):
    FLASH_DUMP = "flash_dump"
    APP_PARTITION = "app_partition"
    ELF = "elf"
    UNKNOWN = "unknown"


class Segment(BaseModel):
    index: int
    file_offset: int = Field(description="Offset of segment data within the input file.")
    load_addr: int = Field(description="Virtual address the segment loads at. Mandatory.")
    length: int
    region: str | None = Field(
        default=None, description="SOC memory region the load address falls in."
    )
    executable: bool = False


class ImageHeader(BaseModel):
    """esp_image_header_t, 24 bytes."""

    magic: int
    segment_count: int
    spi_mode: str
    spi_speed: str
    spi_size: str
    entry_addr: int
    chip_id: int
    chip_id_name: str | None
    min_chip_rev: int
    min_chip_rev_full: int
    max_chip_rev_full: int
    hash_appended: bool


class AppDescriptor(BaseModel):
    """esp_app_desc_t.

    Magic word 0xABCD5432, verified against
    components/esp_app_format/include/esp_app_desc.h.
    """

    magic_word: int
    secure_version: int
    version: str
    project_name: str
    time: str
    date: str
    idf_ver: str
    app_elf_sha256: str


class AppImage(BaseModel):
    """One Espressif application (or bootloader) image within the input."""

    role: str = Field(description="'app' or 'bootloader'.")
    partition_label: str | None = None
    file_offset: int
    image_len: int = Field(description="Length on flash including checksum and hash.")
    header: ImageHeader
    segments: list[Segment]
    checksum_valid: bool | None = None
    sha256_valid: bool | None = None
    sha256: str | None = Field(default=None, description="SHA-256 of the image bytes.")
    app_desc: AppDescriptor | None = None
    notes: list[str] = Field(default_factory=list)


class Partition(BaseModel):
    label: str
    type: int
    type_name: str
    subtype: int
    subtype_name: str
    offset: int
    size: int
    encrypted: bool
    present_in_file: bool = Field(
        description="False when the dump is truncated before this partition."
    )


class ParseResult(BaseModel):
    """What `flash-info` reports."""

    path: str
    size: int
    sha256: str
    input_kind: InputKind
    chip: str | None = None
    chip_candidates: list[Candidate[str]] = Field(default_factory=list)
    partition_table_offset: int | None = None
    flash_base_offset: int | None = Field(
        default=None,
        description="Flash address of the input file's first byte when the dump "
        "does not start at 0x0. Partition offsets remain absolute flash "
        "addresses; file offsets are partition offset minus this value.",
    )
    partitions: list[Partition] = Field(default_factory=list)
    images: list[AppImage] = Field(default_factory=list)
    selected_image: int | None = Field(
        default=None,
        description="Index into `images` that downstream stages analyse by default.",
    )
    ota_slots_identical: bool | None = Field(
        default=None,
        description="For multi-app-partition dumps: whether the OTA slots hold the "
        "same image. Differing slots mean the choice of slot changes the answer.",
    )
    warnings: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None


__all__ = [
    "AppDescriptor",
    "AppImage",
    "Candidate",
    "Evidence",
    "ImageHeader",
    "InputKind",
    "ParseResult",
    "Partition",
    "Segment",
]
