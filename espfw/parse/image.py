"""esp_image_header_t / esp_image_segment_header_t / esp_app_desc_t parsing.

Layout per `components/bootloader_support/include/esp_app_format.h`:
24-byte image header, then per segment an 8-byte header (load_addr, data_len)
followed by data. After the last segment the image is padded so the 1-byte XOR
checksum lands on the last byte of a 16-byte aligned block; if `hash_appended`
is set, a 32-byte SHA-256 of everything up to and including that checksum
follows.
"""

from __future__ import annotations

import hashlib
import struct

from espfw.parse.models import AppDescriptor, AppImage, ImageHeader, Segment
from espfw.soc.chips import Chip, chip_by_id, region_for_address

IMAGE_MAGIC = 0xE9
IMAGE_HEADER_SIZE = 24
SEGMENT_HEADER_SIZE = 8
MAX_SEGMENTS = 16
CHECKSUM_SEED = 0xEF

APP_DESC_MAGIC = 0xABCD5432
APP_DESC_SIZE = 256
# The descriptor sits at the very start of the DROM segment's data, which for a
# normal application is the first segment.
APP_DESC_OFFSET = IMAGE_HEADER_SIZE + SEGMENT_HEADER_SIZE

SPI_MODES = {0: "qio", 1: "qout", 2: "dio", 3: "dout", 4: "fast_read", 5: "slow_read"}
SPI_SPEEDS = {0: "div_2", 1: "div_3", 2: "div_4", 0xF: "div_1"}
SPI_SIZES = {
    0: "1MB",
    1: "2MB",
    2: "4MB",
    3: "8MB",
    4: "16MB",
    5: "32MB",
    6: "64MB",
    7: "128MB",
}


def looks_like_image(data: bytes, offset: int = 0) -> bool:
    """Cheap check before committing to a full parse."""
    if offset + IMAGE_HEADER_SIZE > len(data):
        return False
    if data[offset] != IMAGE_MAGIC:
        return False
    seg_count = data[offset + 1]
    return 1 <= seg_count <= MAX_SEGMENTS


def parse_header(data: bytes, offset: int = 0) -> ImageHeader:
    (
        magic,
        segment_count,
        spi_mode,
        speed_size,
        entry_addr,
        _wp_pin,
        _drv0,
        _drv1,
        _drv2,
        chip_id,
        min_chip_rev,
        min_chip_rev_full,
        max_chip_rev_full,
        _res0,
        _res1,
        _res2,
        _res3,
        hash_appended,
    ) = struct.unpack_from("<BBBBIBBBBHBHHBBBBB", data, offset)

    chip = chip_by_id(chip_id)
    return ImageHeader(
        magic=magic,
        segment_count=segment_count,
        spi_mode=SPI_MODES.get(spi_mode, f"0x{spi_mode:02x}"),
        spi_speed=SPI_SPEEDS.get(speed_size & 0xF, f"0x{speed_size & 0xF:x}"),
        spi_size=SPI_SIZES.get(speed_size >> 4, f"0x{speed_size >> 4:x}"),
        entry_addr=entry_addr,
        chip_id=chip_id,
        chip_id_name=chip.name if chip else None,
        min_chip_rev=min_chip_rev,
        min_chip_rev_full=min_chip_rev_full,
        max_chip_rev_full=max_chip_rev_full,
        hash_appended=bool(hash_appended & 1),
    )


def parse_app_descriptor(data: bytes, offset: int) -> AppDescriptor | None:
    """Parse esp_app_desc_t at an absolute file offset, if the magic matches."""
    if offset + APP_DESC_SIZE > len(data):
        return None
    (magic,) = struct.unpack_from("<I", data, offset)
    if magic != APP_DESC_MAGIC:
        return None

    (secure_version,) = struct.unpack_from("<I", data, offset + 4)
    # offset+8 .. offset+16 is reserv1.
    def _s(rel: int, size: int) -> str:
        raw = data[offset + rel : offset + rel + size]
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

    return AppDescriptor(
        magic_word=magic,
        secure_version=secure_version,
        version=_s(16, 32),
        project_name=_s(48, 32),
        time=_s(80, 16),
        date=_s(96, 16),
        idf_ver=_s(112, 32),
        app_elf_sha256=data[offset + 144 : offset + 176].hex(),
    )


def parse_image(
    data: bytes,
    offset: int,
    chip: Chip | None = None,
    role: str = "app",
    partition_label: str | None = None,
) -> AppImage:
    """Parse one image starting at `offset` within `data`."""
    header = parse_header(data, offset)
    notes: list[str] = []

    pos = offset + IMAGE_HEADER_SIZE
    segments: list[Segment] = []
    for i in range(header.segment_count):
        if pos + SEGMENT_HEADER_SIZE > len(data):
            notes.append(
                f"truncated: segment {i} header runs past end of input; "
                f"{len(segments)} of {header.segment_count} segments recovered"
            )
            break
        load_addr, data_len = struct.unpack_from("<II", data, pos)
        seg_data_off = pos + SEGMENT_HEADER_SIZE
        if seg_data_off + data_len > len(data):
            notes.append(
                f"truncated: segment {i} data ({data_len} bytes at 0x{load_addr:08x}) "
                "runs past end of input"
            )
            data_len = max(0, len(data) - seg_data_off)

        region = region_for_address(chip, load_addr) if chip else None
        segments.append(
            Segment(
                index=i,
                file_offset=seg_data_off,
                load_addr=load_addr,
                length=data_len,
                region=region.name if region else None,
                executable=bool(region and region.executable),
            )
        )
        pos = seg_data_off + data_len

    # Checksum byte is the last byte of the 16-byte aligned block containing it.
    unpadded = pos - offset
    checksum_off = offset + ((unpadded + 16) & ~15) - 1
    image_len = checksum_off + 1 - offset

    checksum_valid: bool | None = None
    if checksum_off < len(data):
        calc = CHECKSUM_SEED
        for seg in segments:
            for b in data[seg.file_offset : seg.file_offset + seg.length]:
                calc ^= b
        checksum_valid = (calc & 0xFF) == data[checksum_off]

    sha256_valid: bool | None = None
    digest: str | None = None
    if header.hash_appended:
        hash_off = offset + image_len
        if hash_off + 32 <= len(data):
            calc = hashlib.sha256(data[offset : offset + image_len]).digest()
            stored = data[hash_off : hash_off + 32]
            sha256_valid = calc == stored
            digest = stored.hex()
            image_len += 32
        else:
            notes.append("hash_appended set but the appended SHA-256 is not in the input")

    app_desc = parse_app_descriptor(data, offset + APP_DESC_OFFSET)
    if app_desc is None and role == "app":
        # Fall back to scanning segment starts: the descriptor is at the head of
        # the DROM segment, which is only conventionally the first one.
        for seg in segments:
            found = parse_app_descriptor(data, seg.file_offset)
            if found:
                app_desc = found
                notes.append(
                    f"app descriptor found at segment {seg.index}, not the "
                    "conventional first-segment offset"
                )
                break

    return AppImage(
        role=role,
        partition_label=partition_label,
        file_offset=offset,
        image_len=image_len,
        header=header,
        segments=segments,
        checksum_valid=checksum_valid,
        sha256_valid=sha256_valid,
        sha256=digest,
        app_desc=app_desc,
        notes=notes,
    )
