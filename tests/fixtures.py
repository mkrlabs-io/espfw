"""Synthetic Espressif images for golden-file tests.

These are built from the struct definitions independently of the parser, so a
parser bug does not quietly agree with itself. Real self-built firmware from a
Docker corpus build is the stronger test; this covers the layouts that are
awkward to produce on demand (moved partition table, differing OTA slots,
truncated dumps).
"""

from __future__ import annotations

import hashlib
import struct

IMAGE_MAGIC = 0xE9
APP_DESC_MAGIC = 0xABCD5432
PART_MAGIC = b"\xaa\x50"

CHIP_IDS = {"esp32": 0x0000, "esp32s2": 0x0002, "esp32s3": 0x0009, "esp32c3": 0x0005}

# Load addresses that fall inside the real region maps for each chip.
LAYOUTS = {
    "esp32": [(0x3F400020, "drom"), (0x400D0020, "irom"), (0x40080000, "iram")],
    "esp32s2": [(0x3F000020, "drom"), (0x40080020, "irom"), (0x40024000, "iram")],
    "esp32s3": [(0x3C000020, "drom"), (0x42000020, "irom"), (0x40378000, "iram")],
    "esp32c3": [(0x3C000020, "drom"), (0x42000020, "irom")],
}


def app_descriptor(
    idf_ver: str = "v5.4",
    project_name: str = "hello_world",
    version: str = "1.0.0",
    date: str = "Jan  1 2026",
    time: str = "12:00:00",
    secure_version: int = 0,
    elf_sha256: bytes | None = None,
) -> bytes:
    """A 256-byte esp_app_desc_t."""

    def field(s: str, n: int) -> bytes:
        return s.encode()[: n - 1].ljust(n, b"\x00")

    out = struct.pack("<II", APP_DESC_MAGIC, secure_version)
    out += b"\x00" * 8  # reserv1[2]
    out += field(version, 32)
    out += field(project_name, 32)
    out += field(time, 16)
    out += field(date, 16)
    out += field(idf_ver, 32)
    out += (elf_sha256 or bytes(range(32)))[:32].ljust(32, b"\x00")
    out += b"\x00" * 80  # reserv2[20]
    assert len(out) == 256, len(out)
    return out


def build_image(
    chip: str = "esp32",
    idf_ver: str | None = "v5.4",
    segments: list[tuple[int, bytes]] | None = None,
    hash_appended: bool = True,
    entry_addr: int = 0x400D0100,
    min_chip_rev_full: int = 0,
    corrupt_checksum: bool = False,
) -> bytes:
    """Build one application image (esp_image_header_t + segments + checksum)."""
    if segments is None:
        drom = app_descriptor(idf_ver=idf_ver) if idf_ver else b"\x00" * 256
        drom += b"a synthetic drom segment\x00" * 4
        layout = LAYOUTS[chip]
        segments = [
            (layout[0][0] - 0x20, drom),
            (layout[1][0], b"\x36\x41\x00" + b"\x00" * 61),  # entry a1,32; padding
        ]
        if len(layout) > 2:
            segments.append((layout[2][0], b"\x0d\xf0" * 32))  # nop.n x 32

    header = struct.pack(
        "<BBBBIBBBBHBHHBBBBB",
        IMAGE_MAGIC,
        len(segments),
        2,  # spi_mode dio
        (2 << 4) | 0xF,  # spi_size 4MB, spi_speed div_1
        entry_addr,
        0xEE,  # wp_pin disabled
        0, 0, 0,  # spi_pin_drv
        CHIP_IDS[chip],
        min_chip_rev_full // 100,
        min_chip_rev_full,
        0xFFFF,
        0, 0, 0, 0,  # reserved[4]
        1 if hash_appended else 0,
    )
    assert len(header) == 24, len(header)

    body = b""
    checksum = 0xEF
    for load_addr, data in segments:
        body += struct.pack("<II", load_addr, len(data)) + data
        for b in data:
            checksum ^= b

    out = header + body
    pad = (-(len(out) + 1)) % 16
    out += b"\x00" * pad
    out += bytes([(checksum ^ 0xFF) if corrupt_checksum else checksum])

    if hash_appended:
        out += hashlib.sha256(out).digest()
    return out


def partition_entry(
    label: str, ptype: int, subtype: int, offset: int, size: int, encrypted: bool = False
) -> bytes:
    return (
        PART_MAGIC
        + bytes([ptype, subtype])
        + struct.pack("<II", offset, size)
        + label.encode()[:15].ljust(16, b"\x00")
        + struct.pack("<I", 1 if encrypted else 0)
    )


DEFAULT_PARTITIONS = [
    ("nvs", 1, 0x02, 0x9000, 0x6000),
    ("phy_init", 1, 0x01, 0xF000, 0x1000),
    ("factory", 0, 0x00, 0x10000, 0x100000),
]

OTA_PARTITIONS = [
    ("nvs", 1, 0x02, 0x9000, 0x4000),
    ("otadata", 1, 0x00, 0xD000, 0x2000),
    ("phy_init", 1, 0x01, 0xF000, 0x1000),
    ("ota_0", 0, 0x10, 0x10000, 0x100000),
    ("ota_1", 0, 0x11, 0x110000, 0x100000),
]


def build_flash_dump(
    chip: str = "esp32",
    partitions: list[tuple[str, int, int, int, int]] | None = None,
    table_offset: int = 0x8000,
    idf_ver: str | None = "v5.4",
    slot_variants: dict[str, str] | None = None,
    include_bootloader: bool = True,
    truncate_at: int | None = None,
    with_md5: bool = True,
) -> bytes:
    """Build a flash dump: bootloader, partition table, and app partitions.

    `slot_variants` maps a partition label to the idf_ver written into that
    slot's descriptor, which is how differing-OTA-slot dumps get made.
    """
    partitions = partitions or DEFAULT_PARTITIONS
    total = max(off + size for _, _, _, off, size in partitions)
    flash = bytearray(b"\xff" * total)

    if include_bootloader:
        boot = build_image(chip=chip, idf_ver=None, entry_addr=0x40080000)
        flash[0x1000 : 0x1000 + len(boot)] = boot

    table = b""
    for label, ptype, subtype, off, size in partitions:
        table += partition_entry(label, ptype, subtype, off, size)
    if with_md5:
        table += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(table).digest()
    flash[table_offset : table_offset + len(table)] = table

    for label, ptype, _subtype, off, _size in partitions:
        if ptype != 0:
            continue
        ver = (slot_variants or {}).get(label, idf_ver)
        img = build_image(chip=chip, idf_ver=ver)
        flash[off : off + len(img)] = img

    out = bytes(flash)
    return out[:truncate_at] if truncate_at else out
