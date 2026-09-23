"""Input classification and structural parsing.

The input may be a full flash dump, a single app partition, or an ELF someone
converted. Everything downstream assumes it knows which, plus correct load
addresses, so this module's job is to remove that ambiguity or say plainly that
it could not.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from espfw import elfreader, provenance
from espfw.errors import ParseError, UnsupportedTargetError
from espfw.models import Candidate, Confidence, Evidence
from espfw.parse import image as image_mod
from espfw.parse import partition as part_mod
from espfw.parse.models import (
    AppImage,
    ImageHeader,
    InputKind,
    ParseResult,
    Partition,
    Segment,
)
from espfw.soc.chips import CHIPS, Arch, chip_by_id

# Xtensa parts put the second-stage bootloader here. (RISC-V parts use 0x0000,
# but those are refused before we get this far.)
BOOTLOADER_OFFSET = 0x1000


def parse_file(path: str | Path, select_slot: str | None = None) -> ParseResult:
    """Parse `path` into a normalized structural description.

    `select_slot` picks which app partition downstream stages analyse by label
    (e.g. "ota_1"); by default the factory partition is preferred, then ota_0.
    """
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ParseError(f"cannot read {p}: {exc}") from exc

    if not data:
        raise ParseError(f"{p} is empty")

    result = ParseResult(
        path=str(p),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        input_kind=InputKind.UNKNOWN,
    )

    if elfreader.is_elf(data):
        _parse_elf(data, result)
    else:
        _parse_flash(data, result, select_slot)

    result.provenance = provenance.current()
    return result


# --- ELF input ---------------------------------------------------------------


def _parse_elf(data: bytes, result: ParseResult) -> None:
    result.input_kind = InputKind.ELF
    elf = elfreader.Elf32(data, origin=result.path)

    if elf.e_machine == elfreader.EM_RISCV:
        raise UnsupportedTargetError(
            "this is a RISC-V ELF; espfw v1 supports the Xtensa parts only "
            "(ESP32, ESP32-S2, ESP32-S3)",
            remedy="RISC-V targets (C2/C3/C5/C6/H2/P4) are not supported.",
        )
    if elf.e_machine != elfreader.EM_XTENSA:
        raise UnsupportedTargetError(
            f"ELF e_machine is {elf.e_machine}, not Xtensa (94); this is not an "
            "Espressif Xtensa image"
        )

    # An ELF has no image header, so the chip must come from the address space.
    alloc = [s for s in elf.sections if s.is_alloc and s.addr]
    cands = _chip_from_addresses([s.addr for s in alloc])
    result.chip_candidates = cands
    if cands:
        result.chip = cands[0].value
    else:
        result.warnings.append(
            "could not infer chip variant from section addresses; region "
            "naming will be unavailable"
        )

    chip = CHIPS[result.chip] if result.chip else None
    segments: list[Segment] = []
    for section in alloc:
        body = section.data()
        if not body:
            continue
        region = image_mod.region_for_address(chip, section.addr) if chip else None
        segments.append(
            Segment(
                index=len(segments),
                file_offset=section.offset,
                load_addr=section.addr,
                length=len(body),
                region=region.name if region else None,
                executable=section.is_code or bool(region and region.executable),
            )
        )

    # Normalize allocatable ELF sections into the same image shape downstream
    # analysis consumes for a .bin. Header-only fields are explicitly unknown;
    # entry and load addresses come from the ELF itself.
    result.images = [
        AppImage(
            role="app",
            file_offset=0,
            image_len=len(data),
            header=ImageHeader(
                magic=0,
                segment_count=len(segments),
                spi_mode="unknown",
                spi_speed="unknown",
                spi_size="unknown",
                entry_addr=elf.e_entry,
                chip_id=chip.chip_id if chip else 0,
                chip_id_name=chip.name if chip else None,
                min_chip_rev=0,
                min_chip_rev_full=0,
                max_chip_rev_full=0,
                hash_appended=False,
            ),
            segments=segments,
            checksum_valid=None,
            sha256_valid=None,
            sha256=result.sha256,
            notes=["constructed from allocatable ELF sections"],
        )
    ]
    result.selected_image = 0

    result.warnings.append(
        "ELF input: segments are taken from allocatable sections, and there is "
        "no esp_image_header_t or app descriptor to cross-check against"
    )


# --- flash dump / app partition ---------------------------------------------


def _parse_flash(data: bytes, result: ParseResult, select_slot: str | None) -> None:
    table = part_mod.find_table(data)
    images: list[AppImage] = []

    if table:
        offset, partitions = table
        base = _infer_flash_base(data, offset, partitions)
        result.input_kind = InputKind.FLASH_DUMP
        result.partition_table_offset = offset
        result.flash_base_offset = base or None
        result.partitions = partitions
        if base:
            result.warnings.append(
                f"this dump appears to start at flash address 0x{base:x}; "
                f"partition file offsets are shifted by -0x{base:x}"
            )
        if offset + base != part_mod.DEFAULT_OFFSET:
            result.warnings.append(
                f"partition table at flash 0x{offset + base:x} (file 0x{offset:x}), "
                "not the conventional 0x8000 "
                "(CONFIG_PARTITION_TABLE_OFFSET was changed)"
            )
        for part in partitions:
            part.present_in_file = part.offset >= base and part.offset - base < len(data)

        boot_file_offset = BOOTLOADER_OFFSET - base
        if 0 <= boot_file_offset < len(data) and image_mod.looks_like_image(
            data, boot_file_offset
        ):
            images.append(
                image_mod.parse_image(
                    data, boot_file_offset, role="bootloader"
                )
            )

        for part in partitions:
            if part.type != part_mod.APP_TYPE:
                continue
            file_offset = part.offset - base
            if file_offset < 0:
                result.warnings.append(
                    f"app partition '{part.label}' at 0x{part.offset:x} precedes "
                    "the start of this dump; it was not analysed"
                )
                continue
            if not part.present_in_file:
                result.warnings.append(
                    f"app partition '{part.label}' at 0x{part.offset:x} is beyond "
                    "the end of this dump; it was not analysed"
                )
                continue
            if not image_mod.looks_like_image(data, file_offset):
                result.warnings.append(
                    f"app partition '{part.label}' at 0x{part.offset:x} holds no "
                    "valid image header (erased, encrypted, or not yet flashed)"
                )
                continue
            images.append(
                image_mod.parse_image(
                    data, file_offset, role="app", partition_label=part.label
                )
            )

    elif image_mod.looks_like_image(data, 0):
        result.input_kind = InputKind.APP_PARTITION
        images.append(image_mod.parse_image(data, 0, role="app"))

    else:
        raise ParseError(
            "input is neither an ELF, a flash dump with a partition table, nor a "
            "bare application image (no 0xE9 magic at offset 0)",
            remedy="If this is an encrypted flash dump, decrypt it first; espfw "
            "cannot analyse flash-encrypted images.",
        )

    if not images:
        raise ParseError(
            "a partition table was found but no analysable application image; "
            "every app partition was missing, erased, or encrypted"
        )

    # Chip: the header field is the primary claim, load addresses corroborate.
    _resolve_chip(images, result)

    chip = CHIPS[result.chip] if result.chip else None
    if chip and chip.arch is Arch.RISCV:
        raise UnsupportedTargetError(
            f"image targets {chip.name}, a RISC-V part; espfw v1 supports the "
            "Xtensa parts only (ESP32, ESP32-S2, ESP32-S3)",
            remedy="RISC-V targets are not supported. Analysing them "
            "with the Xtensa decoder would produce garbage, so espfw stops here.",
        )

    # Region names need the chip, so segments are annotated on a second pass.
    if chip:
        for img in images:
            for seg in img.segments:
                region = image_mod.region_for_address(chip, seg.load_addr)
                seg.region = region.name if region else None
                seg.executable = bool(region and region.executable)

    result.images = images
    result.selected_image = _select_image(images, select_slot)
    _check_ota_slots(images, result)


def _infer_flash_base(
    data: bytes, table_offset: int, partitions: list[Partition]
) -> int:
    """Detect dumps that omit the first sector(s) of flash.

    Partition entries carry absolute flash addresses. A dump that starts at
    0x1000 therefore holds the conventional table at file offset 0x7000 and the
    factory partition at a file offset one sector earlier than its table offset.
    The base is inferred only when the normal mapping finds no app images but a
    shifted mapping does.
    """
    apps = [part for part in partitions if part.type == part_mod.APP_TYPE]
    if not apps:
        return 0

    def found(base: int) -> int:
        count = 0
        for part in apps:
            file_offset = part.offset - base
            if 0 <= file_offset < len(data) and image_mod.looks_like_image(
                data, file_offset
            ):
                count += 1
        return count

    if found(0):
        return 0

    candidates: list[int] = []
    if table_offset < part_mod.DEFAULT_OFFSET:
        candidates.append(part_mod.DEFAULT_OFFSET - table_offset)
    candidates.append(0x1000)
    for base in sorted(set(candidates)):
        if base and found(base):
            return base
    return 0


def _resolve_chip(images: list[AppImage], result: ParseResult) -> None:
    """Decide the chip from the header id, corroborated by load addresses."""
    app = next((i for i in images if i.role == "app"), images[0])
    header_chip = chip_by_id(app.header.chip_id)

    addrs = [s.load_addr for i in images for s in i.segments]
    addr_cands = _chip_from_addresses(addrs)

    cands: list[Candidate[str]] = []
    if header_chip:
        # chip_id 0 is ESP32, but it is also what a pre-chip_id image carries in
        # those bytes — so the same value is strong evidence when nonzero and
        # merely consistent when zero.
        strong = header_chip.chip_id != 0
        cands.append(
            Candidate[str](
                value=header_chip.name,
                score=1.0 if strong else 0.6,
                confidence=Confidence.HIGH if strong else Confidence.MEDIUM,
                source="image_header",
                evidence=[
                    Evidence(
                        kind="chip_id",
                        detail=f"esp_image_header_t.chip_id = 0x{app.header.chip_id:04x}"
                        + ("" if strong else " (also the value in pre-chip_id images)"),
                    )
                ],
            )
        )

    for cand in addr_cands:
        existing = next((c for c in cands if c.value == cand.value), None)
        if existing:
            existing.score += cand.score
            existing.evidence.extend(cand.evidence)
        else:
            cands.append(cand)

    cands.sort(key=lambda c: -c.score)
    result.chip_candidates = cands

    if not cands:
        result.warnings.append("could not determine chip variant")
        return

    result.chip = cands[0].value
    if header_chip and addr_cands and addr_cands[0].value != header_chip.name:
        result.warnings.append(
            f"chip disagreement: header says {header_chip.name}, segment load "
            f"addresses look like {addr_cands[0].value}"
        )


def _chip_from_addresses(addrs: list[int]) -> list[Candidate[str]]:
    """Rank Xtensa chips by how well their address space explains `addrs`.

    Only load addresses that fall in *some* named region count. The chips'
    address maps overlap substantially, so this corroborates the header rather
    than replacing it.
    """
    from espfw.soc.chips import region_for_address

    interesting = [a for a in addrs if a]
    if not interesting:
        return []

    out: list[Candidate[str]] = []
    for chip in CHIPS.values():
        if chip.arch is not Arch.XTENSA:
            continue
        hits = [a for a in interesting if region_for_address(chip, a)]
        if not hits:
            continue
        ratio = len(hits) / len(interesting)
        out.append(
            Candidate[str](
                value=chip.name,
                score=ratio,
                confidence=(
                    Confidence.HIGH
                    if ratio == 1.0
                    else Confidence.MEDIUM
                    if ratio >= 0.5
                    else Confidence.LOW
                ),
                source="load_addresses",
                evidence=[
                    Evidence(
                        kind="address_coverage",
                        detail=f"{len(hits)}/{len(interesting)} load addresses fall "
                        f"in a named {chip.name} region",
                        weight=ratio,
                    )
                ],
            )
        )

    out.sort(key=lambda c: -c.score)
    # A tie tells us nothing; report only a clear winner.
    if len(out) > 1 and out[0].score == out[1].score:
        for c in out:
            c.confidence = Confidence.LOW
    return out


def _select_image(images: list[AppImage], select_slot: str | None) -> int | None:
    """Choose the app image downstream stages analyse."""
    apps = [(i, img) for i, img in enumerate(images) if img.role == "app"]
    if not apps:
        return None

    if select_slot:
        for i, img in apps:
            if img.partition_label == select_slot:
                return i
        raise ParseError(
            f"no app partition labelled '{select_slot}'; available: "
            + ", ".join(str(img.partition_label) for _, img in apps)
        )

    for want in ("factory", "ota_0"):
        for i, img in apps:
            if img.partition_label == want:
                return i
    return apps[0][0]


def _check_ota_slots(images: list[AppImage], result: ParseResult) -> None:
    """Flag OTA slots holding different images.

    Two populated slots that differ mean the analysis answers a question about
    one slot only — which slot is running is a runtime fact this tool cannot
    see, so the user has to be told to choose.
    """
    apps = [img for img in images if img.role == "app"]
    if len(apps) < 2:
        return

    fingerprints = {
        img.sha256 or f"len:{img.image_len}:entry:{img.header.entry_addr}" for img in apps
    }
    result.ota_slots_identical = len(fingerprints) == 1
    if not result.ota_slots_identical:
        labels = ", ".join(str(img.partition_label) for img in apps)
        chosen = images[result.selected_image].partition_label if result.selected_image is not None else "?"
        result.warnings.append(
            f"{len(apps)} populated app partitions ({labels}) hold different "
            f"images; analysing '{chosen}'. Use --slot to pick another."
        )
