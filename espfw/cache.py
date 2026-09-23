"""Cache locations.

One root holds both the signature corpus and the memoized boundary-recovery
results. Recovery takes seconds, but it is asked for the same function list on
every run, so it is memoized; its inputs are fully described by (image bytes,
chip, recovery version, canonicalizer version). Corpus builds are never
implicit.
"""

from __future__ import annotations

import os
from pathlib import Path


def cache_root(override: Path | None = None) -> Path:
    if override:
        root = Path(override)
    elif env := os.environ.get("ESPFW_CACHE_DIR"):
        root = Path(env)
    else:
        base = os.environ.get("XDG_CACHE_HOME")
        root = Path(base) / "espfw" if base else Path.home() / ".cache" / "espfw"
    root.mkdir(parents=True, exist_ok=True)
    return root


def corpus_db(override: Path | None = None) -> Path:
    return cache_root(override) / "corpus.sqlite"


def boundaries_dir(override: Path | None = None) -> Path:
    d = cache_root(override) / "boundaries"
    d.mkdir(parents=True, exist_ok=True)
    return d
