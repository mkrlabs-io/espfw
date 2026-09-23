"""Stable sdkconfig normalization used by corpus build keys."""

from __future__ import annotations

import hashlib


def normalize_config(text: str) -> str:
    """Canonical text form, ignoring comments, blank lines, and ordering."""
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return "\n".join(sorted(lines)) + "\n"


def config_hash(text: str) -> str:
    return hashlib.sha256(normalize_config(text).encode()).hexdigest()
