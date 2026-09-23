"""Corpus builds via the official ESP-IDF Docker images.

Explicit by design. A build takes minutes to hours, so it never happens as a
side effect of an analysis command — `symbols` with an empty corpus fails with
the exact command to run instead.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from espfw import provenance
from espfw.corpus.config import config_hash
from espfw.corpus.harvest import harvest_archive, harvest_linked_elf
from espfw.corpus.models import BuildKey, BuildResult
from espfw.corpus.store import open_store
from espfw.disasm.toolchain import find_objdump, objdump_version, toolchain_id
from espfw.errors import CorpusBuildError, ToolchainError
from espfw.soc.chips import CHIPS, Arch

BUILD_SCRIPT = Path(__file__).parent / "docker_build.sh"
IMAGE_TEMPLATE = "espressif/idf:{version}"

PRESETS: dict[str, str] = {
    # The image's own hello_world defaults: no sdkconfig.defaults at all.
    "default": "",
    # Size-optimized, the common shipping choice.
    "size": "CONFIG_COMPILER_OPTIMIZATION_SIZE=y\n",
    "perf": "CONFIG_COMPILER_OPTIMIZATION_PERF=y\n",
    "unicore": "CONFIG_FREERTOS_UNICORE=y\n",
}


def _resolve_config(config: str) -> tuple[str, str]:
    """Return (name, sdkconfig.defaults text) for a preset name or file path."""
    if config in PRESETS:
        return config, PRESETS[config]
    path = Path(config)
    if path.is_file():
        return path.name, path.read_text()
    raise CorpusBuildError(
        f"config '{config}' is neither a preset nor a readable file",
        remedy="Presets: " + ", ".join(sorted(PRESETS)) + ". Otherwise pass a path "
        "to an sdkconfig or sdkconfig.defaults file.",
    )


def _require_docker() -> None:
    if shutil.which("docker") is None:
        raise CorpusBuildError(
            "docker was not found on PATH",
            remedy="Corpus builds run inside the official espressif/idf images. "
            "Install Docker, or build the artifacts yourself and harvest them "
            "with the Python API in espfw.corpus.harvest.",
        )


def _ensure_image(image: str, verbose: bool = False) -> None:
    have = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True, check=False
    )
    if have.returncode == 0:
        return
    # Image pulls are the one network access an explicit corpus build is
    # allowed to make.
    pull = subprocess.run(
        ["docker", "pull", image], capture_output=not verbose, text=True, check=False
    )
    if pull.returncode != 0:
        raise CorpusBuildError(
            f"could not pull {image}",
            remedy="Check the version tag exists at hub.docker.com/r/espressif/idf/tags. "
            "Official images do not reach back indefinitely; very old IDF releases "
            "need a source-checkout build instead.",
        )


@contextlib.contextmanager
def _run_docker_build(
    image: str, chip: str, defaults_text: str, jobs: int, verbose: bool
) -> Iterator[Path]:
    """Run one SDK build in `image` and yield its export directory.

    The directory is temporary: everything worth keeping is harvested into the
    store before this returns.
    """
    with tempfile.TemporaryDirectory(prefix="espfw-corpus-") as tmp:
        out = Path(tmp)
        if defaults_text:
            (out / "sdkconfig.defaults").write_text(defaults_text)
        argv = [
            "docker", "run", "--rm",
            "-v", f"{out}:/out",
            "-v", f"{BUILD_SCRIPT}:/espfw_build.sh:ro",
            "-e", f"ESPFW_JOBS={jobs}",
            image,
            "bash", "/espfw_build.sh", chip,
        ]
        proc = subprocess.run(argv, capture_output=not verbose, text=True, check=False)
        if proc.returncode != 0:
            tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()[-30:]
            raise CorpusBuildError(
                f"the ESP-IDF build failed in {image}",
                remedy="Build output tail:\n  " + "\n  ".join(tail),
            )
        yield out


def harvest_artifacts(
    artifacts: Path,
    version: str,
    chip: str = "esp32",
    config_name: str = "external",
    cache_dir: Path | None = None,
) -> BuildResult:
    """Harvest an existing build tree instead of running Docker.

    The layout is the one `docker_build.sh` produces: `archives/*.a`, `app/*.elf`
    and `sdkconfig.out`. This is the escape hatch for IDF versions the official
    images do not reach and for users who already have a build.
    """
    started = time.monotonic()
    od_version = objdump_version(str(find_objdump(chip)))
    return _harvest_and_store(
        out=artifacts,
        version=version,
        chip=chip,
        toolchain=_build_toolchain(artifacts, toolchain_id(chip)),
        od_version=od_version,
        config_name=config_name,
        image=None,
        cache_dir=cache_dir,
        duration=time.monotonic() - started,
    )


def build_corpus(
    version: str,
    config: str = "default",
    chip: str = "esp32",
    jobs: int = 0,
    cache_dir: Path | None = None,
    verbose: bool = False,
) -> BuildResult:
    """Build one (version, config, chip) and harvest its signatures."""
    chip_info = CHIPS.get(chip)
    if chip_info is None:
        raise CorpusBuildError(f"unknown chip '{chip}'")
    if chip_info.arch is not Arch.XTENSA:
        raise CorpusBuildError(
            f"{chip} is a RISC-V part, which espfw does not support"
        )

    _require_docker()
    image = IMAGE_TEMPLATE.format(version=version)
    _ensure_image(image, verbose=verbose)

    try:
        # The host objdump decodes both sides of every later comparison.
        # It is recorded in provenance, and is required even though the compile
        # happens in Docker.
        od_version = objdump_version(str(find_objdump(chip)))
        host_toolchain = toolchain_id(chip)
    except ToolchainError as exc:
        raise CorpusBuildError(
            f"the host has no usable Xtensa objdump for {chip}: {exc.message}",
            remedy="Corpus and target must be disassembled by the same engine "
            ", so the host toolchain is required even though the build "
            "itself runs in Docker.",
        ) from exc

    config_name, defaults_text = _resolve_config(config)
    started = time.monotonic()

    with _run_docker_build(image, chip, defaults_text, jobs, verbose) as out:
        return _harvest_and_store(
            out=out,
            version=version,
            chip=chip,
            toolchain=_build_toolchain(out, host_toolchain),
            od_version=od_version,
            config_name=config_name,
            image=image,
            cache_dir=cache_dir,
            duration=time.monotonic() - started,
        )


def _build_toolchain(out: Path, fallback: str) -> str:
    """Identify the toolchain that *compiled* the corpus.

    This is the toolchain axis of the cache key, and it is deliberately not the
    host's objdump: what makes codegen differ wholesale is the compiler the SDK
    was built with, which lives inside the IDF image and moves between IDF patch
    releases. Confusing the two would let two materially different corpora share
    a key and present as "the entire SDK is modified".
    """
    marker = out / "objdump_version.txt"
    if not marker.is_file():
        return fallback
    text = marker.read_text().strip()
    m = re.search(r"\(([^)]*)\)\s*([0-9][\w.]*)", text)
    if not m:
        return text or fallback
    build = m.group(1).replace("crosstool-NG ", "").strip()
    return f"{build}/binutils-{m.group(2)}"


def _harvest_and_store(
    out: Path,
    version: str,
    chip: str,
    toolchain: str,
    od_version: str,
    config_name: str,
    image: str | None,
    cache_dir: Path | None,
    duration: float,
) -> BuildResult:
    warnings: list[str] = []

    resolved = out / "sdkconfig.out"
    if resolved.is_file():
        config_text = resolved.read_text()
    else:
        config_text = ""
        warnings.append(
            "the build produced no resolved sdkconfig; the config hash is "
            "derived from the requested config, which is weaker"
        )

    key = BuildKey(
        idf_version=version,
        config_hash=config_hash(config_text),
        chip=chip,
        toolchain=toolchain,
    )

    harvested = []
    archives = sorted((out / "archives").glob("*.a")) if (out / "archives").is_dir() else []
    for archive in archives:
        harvested.extend(harvest_archive(chip, archive))
    if not archives:
        warnings.append("no .a archives were exported; coverage will be much lower")

    # The linked ELF has no component structure — everything is one image. The
    # archives do, so component is carried across by name.
    component_by_name = {fn.name: fn.component for fn in harvested if fn.component}

    app_dir = out / "app"
    linked = 0
    if app_dir.is_dir():
        for elf in sorted(app_dir.glob("*.elf")):
            found = harvest_linked_elf(chip, elf)
            for fn in found:
                fn.component = component_by_name.get(fn.name)
            harvested.extend(found)
            linked += len(found)

    # A function present in both origins is kept twice on purpose: the archive
    # copy has not been through linker relaxation and the linked copy has, and
    # which one a target image resembles is exactly what we need to observe.
    components: dict[str, int] = {}
    digests: dict[str, set[str]] = {}
    for fn in harvested:
        comp = fn.component or "(unattributed)"
        components[comp] = components.get(comp, 0) + 1
        digests.setdefault(fn.form.digest, set()).add(fn.name)

    duplicate_digests = sum(1 for names in digests.values() if len(names) > 1)

    with open_store(cache_dir) as store:
        build_id = store.create_build(key, config_name, config_text, od_version)
        store.add_functions(
            build_id,
            [
                (fn.name, fn.component, fn.object, fn.origin, fn.vaddr, fn.form)
                for fn in harvested
            ],
        )
        store.commit()

    if duplicate_digests:
        warnings.append(
            f"{duplicate_digests} canonical form(s) are shared by more than one "
            "function name; exact matching cannot distinguish those, and they are "
            "reported as ambiguous rather than guessed"
        )

    return BuildResult(
        key=key,
        config_name=config_name,
        functions_stored=len(harvested),
        archive_functions=len(harvested) - linked,
        linked_functions=linked,
        components=dict(sorted(components.items(), key=lambda kv: -kv[1])[:25]),
        duplicate_digests=duplicate_digests,
        duration_seconds=round(duration, 1),
        docker_image=image,
        warnings=warnings,
        provenance=provenance.current(objdump_version=od_version),
    )
