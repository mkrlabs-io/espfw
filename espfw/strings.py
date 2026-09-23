"""String extraction shared by target analysis and corpus harvesting."""

from __future__ import annotations

MIN_ANCHOR_LEN = 5


def cstr_at(blob: bytes, offset: int, maxlen: int = 128) -> str | None:
    end = blob.find(b"\0", offset, offset + maxlen)
    if end < 0:
        return None
    raw = blob[offset:end]
    if len(raw) < MIN_ANCHOR_LEN:
        return None
    if not all(0x20 <= byte < 0x7F or byte in (9, 10, 13) for byte in raw):
        return None
    return raw.decode("ascii")
