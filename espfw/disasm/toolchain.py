"""Chip -> Xtensa binutils selection.

The corpus and the target must be disassembled by the same engine, from the
matching chip variant's toolchain: any decoding discrepancy shows up later as a
spurious non-match or a spurious "modified" finding, indistinguishable from a
real one. So the toolchain identity is resolved here, once, and recorded in
provenance.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from espfw.errors import ToolchainError
from espfw.soc.chips import CHIPS, Arch, Chip


def _candidate_dirs() -> list[Path]:
    dirs: list[Path] = []
    if env := os.environ.get("ESPFW_TOOLCHAIN_DIR"):
        dirs.append(Path(env))
    tools = Path(os.environ.get("IDF_TOOLS_PATH", Path.home() / ".espressif")) / "tools"
    # Current unified layout, then the older per-chip toolchain directories.
    for pattern in (
        "xtensa-esp-elf/*/xtensa-esp-elf/bin",
        "xtensa-esp32-elf/*/xtensa-esp32-elf/bin",
        "xtensa-esp32s2-elf/*/xtensa-esp32s2-elf/bin",
        "xtensa-esp32s3-elf/*/xtensa-esp32s3-elf/bin",
    ):
        dirs.extend(sorted(tools.glob(pattern), reverse=True))
    return dirs


@lru_cache(maxsize=8)
def find_objdump(chip_name: str) -> Path:
    """Locate the objdump for `chip_name`.

    Espressif's unified toolchain ships per-variant driver names sharing one
    binutils build; the variant name still matters because it selects the
    configured ISA. Falling back to a differently-named objdump is allowed only
    within the Xtensa family, and is reported by `describe_toolchains()`.
    """
    chip = CHIPS.get(chip_name)
    if chip is None:
        raise ToolchainError(f"unknown chip '{chip_name}'")
    if chip.arch is not Arch.XTENSA or not chip.toolchain_prefix:
        raise ToolchainError(
            f"{chip_name} is not an Xtensa part; v1 has no disassembler for it"
        )

    exe = f"{chip.toolchain_prefix}-objdump"

    if env := os.environ.get(f"ESPFW_OBJDUMP_{chip_name.upper()}"):
        return Path(env)

    for d in _candidate_dirs():
        cand = d / exe
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand

    if found := shutil.which(exe):
        return Path(found)

    # Same binutils build, different driver name: acceptable, but say so.
    for other in ("xtensa-esp-elf", "xtensa-esp32-elf"):
        alt = f"{other}-objdump"
        for d in _candidate_dirs():
            cand = d / alt
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        if found := shutil.which(alt):
            return Path(found)

    raise ToolchainError(
        f"no Xtensa objdump found for {chip_name} (looked for {exe})",
        remedy="Install the ESP-IDF tools (`idf_tools.py install xtensa-esp-elf`), "
        "or point ESPFW_TOOLCHAIN_DIR at a directory containing it. Do not "
        "substitute a general-purpose disassembler: Xtensa is a configurable "
        "ISA and non-Espressif decoders mis-decode it silently.",
    )


@lru_cache(maxsize=8)
def objdump_version(objdump: str) -> str:
    """First line of `objdump --version`, for provenance."""
    try:
        out = subprocess.run(
            [objdump, "--version"], capture_output=True, text=True, timeout=30, check=True
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolchainError(f"cannot run {objdump}: {exc}") from exc
    return out.stdout.splitlines()[0].strip()


def toolchain_id(chip: Chip | str) -> str:
    """A stable identifier for the toolchain axis of the corpus key.

    Same IDF version and sdkconfig built with a different toolchain produces
    wholesale codegen differences, so the toolchain is part of the cache key,
    not an afterthought.
    """
    name = chip if isinstance(chip, str) else chip.name
    version = objdump_version(str(find_objdump(name)))
    # "GNU objdump (crosstool-NG esp-13.2.0_20240530) 2.41" -> "esp-13.2.0_20240530/2.41"
    m = re.search(r"\(([^)]*)\)\s*([0-9][\w.]*)", version)
    if m:
        build = m.group(1).replace("crosstool-NG ", "").strip()
        return f"{build}/binutils-{m.group(2)}"
    return version


def describe_toolchains() -> list[str]:
    """Human summary of what is installed, for `espfw version`."""
    lines: list[str] = []
    for name, chip in CHIPS.items():
        if chip.arch is not Arch.XTENSA:
            continue
        try:
            path = find_objdump(name)
            lines.append(f"{name:8s} {objdump_version(str(path))}  [{path}]")
        except ToolchainError as exc:
            lines.append(f"{name:8s} MISSING ({exc.message})")
    return lines
