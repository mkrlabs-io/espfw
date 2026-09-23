"""Partition table parsing.

Format per `components/partition_table/gen_esp32part.py`: 32-byte entries,
magic 0xAA50, terminated by a non-magic entry; an optional MD5 entry marked by
the 0xEBEB pseudo-magic; the table occupies one 4K sector with at most 0xC00 of
entry data.

The conventional offset is 0x8000, but CONFIG_PARTITION_TABLE_OFFSET moves it
and real images do move it — so 0x8000 is tried first and then a scan runs,
rather than being hardcoded blindly.
"""

from __future__ import annotations

import struct

from espfw.parse.models import Partition

MAGIC = b"\xaa\x50"
MD5_MAGIC = b"\xeb\xeb"
ENTRY_SIZE = 32
MAX_ENTRY_BYTES = 0xC00
TABLE_SIZE = 0x1000
DEFAULT_OFFSET = 0x8000

APP_TYPE = 0x00
DATA_TYPE = 0x01

TYPE_NAMES = {APP_TYPE: "app", DATA_TYPE: "data"}

SUBTYPE_NAMES: dict[int, dict[int, str]] = {
    APP_TYPE: {0x00: "factory", 0x20: "test"},
    DATA_TYPE: {
        0x00: "ota",
        0x01: "phy",
        0x02: "nvs",
        0x03: "coredump",
        0x04: "nvs_keys",
        0x05: "efuse",
        0x06: "undefined",
        0x80: "esphttpd",
        0x81: "fat",
        0x82: "spiffs",
        0x83: "littlefs",
    },
}
# ota_0..ota_15 occupy app subtypes 0x10..0x1F.
for _i in range(16):
    SUBTYPE_NAMES[APP_TYPE][0x10 + _i] = f"ota_{_i}"

PART_FLAG_ENCRYPTED = 1 << 0


def _subtype_name(ptype: int, subtype: int) -> str:
    return SUBTYPE_NAMES.get(ptype, {}).get(subtype, f"0x{subtype:02x}")


def parse_table(data: bytes, offset: int, file_size: int) -> list[Partition] | None:
    """Parse a table at `offset`, or return None if there isn't a valid one there."""
    blob = data[offset : offset + TABLE_SIZE]
    if len(blob) < ENTRY_SIZE or blob[0:2] != MAGIC:
        return None

    parts: list[Partition] = []
    for pos in range(0, min(len(blob), MAX_ENTRY_BYTES), ENTRY_SIZE):
        entry = blob[pos : pos + ENTRY_SIZE]
        if len(entry) < ENTRY_SIZE:
            break
        magic = entry[0:2]
        if magic == MD5_MAGIC:
            continue  # table checksum entry, not a partition
        if magic != MAGIC:
            break  # end of table (0xFF padding)

        ptype, subtype = entry[2], entry[3]
        p_offset, p_size = struct.unpack_from("<II", entry, 4)
        label = entry[12:28].split(b"\x00", 1)[0].decode("utf-8", "replace")
        (flags,) = struct.unpack_from("<I", entry, 28)

        parts.append(
            Partition(
                label=label,
                type=ptype,
                type_name=TYPE_NAMES.get(ptype, f"0x{ptype:02x}"),
                subtype=subtype,
                subtype_name=_subtype_name(ptype, subtype),
                offset=p_offset,
                size=p_size,
                encrypted=bool(flags & PART_FLAG_ENCRYPTED),
                present_in_file=p_offset < file_size,
            )
        )

    return parts or None


def find_table(data: bytes) -> tuple[int, list[Partition]] | None:
    """Locate the partition table, preferring the conventional offset.

    The scan is bounded to the first 1 MB and to 4K alignment; a partition table
    is always sector-aligned and always precedes the app partitions, so a hit
    beyond that would be a false positive rather than a relocated table.
    """
    result = parse_table(data, DEFAULT_OFFSET, len(data))
    if result:
        return DEFAULT_OFFSET, result

    limit = min(len(data), 1 << 20)
    for off in range(0, limit, 0x1000):
        if data[off : off + 2] != MAGIC:
            continue
        found = parse_table(data, off, len(data))
        if found and _plausible(found):
            return off, found
    return None


def _plausible(parts: list[Partition]) -> bool:
    """Guard the scan against random 0xAA50 bytes inside application data."""
    if not parts:
        return False
    if not any(p.type == APP_TYPE for p in parts):
        return False
    return all(p.size > 0 and p.offset % 0x1000 == 0 for p in parts)
