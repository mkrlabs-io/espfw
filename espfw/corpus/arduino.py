"""Arduino-esp32 corpus builds.

A large share of shipping ESP32 firmware is not built with ESP-IDF directly but
with **arduino-esp32**, which bundles a pinned ESP-IDF underneath its own core
plus whatever libraries the product uses. An ESP-IDF-only corpus identifies the
IDF layer of such an image and leaves the Arduino core and libraries — often most
of the application-adjacent code — unidentified.

The framework is carried in the version string (`arduino-esp32@2.0.14`) rather
than in a new cache axis, so a core is searched and reported like any other
build. An Arduino image's `esp_app_desc.idf_ver` reports the **bundled** IDF
version, not the core version, which the build reports so the two are not
mistaken for a contradiction.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from espfw import provenance
from espfw.corpus.build import _harvest_and_store
from espfw.corpus.config import config_hash
from espfw.corpus.models import BuildResult
from espfw.disasm.toolchain import find_objdump, objdump_version
from espfw.errors import CorpusBuildError

ARDUINO_DIR = Path(__file__).parent / "arduino"
IMAGE_PREFIX = "espfw-arduino"
FRAMEWORK = "arduino-esp32"

# The libraries worth having, by deployment: an ESP32 product built with Arduino
# is very likely to contain several of these. Names are as the Library Manager
# spells them, with '+' standing in for a space so the list survives being passed
# through a Docker build argument.
POPULAR_LIBRARIES: tuple[str, ...] = (
    "ArduinoJson",
    "PubSubClient",
    "WebSockets",
    "Adafruit+NeoPixel",
    "Adafruit+GFX+Library",
    "Adafruit+SSD1306",
    "Adafruit+Unified+Sensor",
    "DHT+sensor+library",
    "OneWire",
    "DallasTemperature",
    "FastLED",
    "NimBLE-Arduino",
)

# Core versions by installed base rather than by recency. 1.0.6 is the last of
# the 1.x line and still extremely common in shipped products; 2.0.14 is the last
# 2.0.x and the most widely deployed modern core; 3.x is current.
POPULAR_CORES: tuple[str, ...] = ("1.0.6", "2.0.14", "3.0.7")


def image_tag(core_version: str) -> str:
    return f"{IMAGE_PREFIX}:{core_version}"


def build_image(
    core_version: str,
    libraries: tuple[str, ...] = POPULAR_LIBRARIES,
    verbose: bool = False,
    rebuild: bool = False,
) -> str:
    """Build (once) the Docker image holding this core and its libraries.

    Installing a core pulls a toolchain and the precompiled ESP-IDF archives —
    minutes and gigabytes. Doing that per corpus build would make the Arduino
    path unusable, so it is an image.
    """
    tag = image_tag(core_version)
    if not rebuild:
        have = subprocess.run(
            ["docker", "image", "inspect", tag], capture_output=True, check=False
        )
        if have.returncode == 0:
            return tag

    argv = [
        "docker", "build", "-t", tag,
        "--build-arg", f"CORE_VERSION={core_version}",
        "--build-arg", "LIBRARIES=" + " ".join(libraries),
        str(ARDUINO_DIR),
    ]
    proc = subprocess.run(argv, capture_output=not verbose, text=True, check=False)
    if proc.returncode != 0:
        tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()[-25:]
        raise CorpusBuildError(
            f"could not build the arduino-esp32 {core_version} image",
            remedy="Docker build output tail:\n  " + "\n  ".join(tail)
            + "\n\nCore versions are listed at "
            "https://github.com/espressif/arduino-esp32/releases",
        )
    return tag


_IDF_PARTS = re.compile(r"ESP_IDF_VERSION_(MAJOR|MINOR|PATCH)=(\d+)")


def bundled_idf_version(out: Path) -> str | None:
    """The ESP-IDF version this core bundles, as `vMAJOR.MINOR.PATCH`.

    This is what the image's app descriptor will claim.
    """
    marker = out / "bundled_idf.txt"
    if not marker.is_file():
        return None
    parts = dict(_IDF_PARTS.findall(marker.read_text()))
    if "MAJOR" not in parts or "MINOR" not in parts:
        return None
    patch = parts.get("PATCH", "0")
    return f"v{parts['MAJOR']}.{parts['MINOR']}.{patch}"


def installed_libraries(out: Path) -> list[str]:
    """Libraries actually present in the image, from arduino-cli's own listing."""
    marker = out / "arduino-libs.txt"
    if not marker.is_file():
        return []
    libs = []
    for line in marker.read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            libs.append(f"{' '.join(parts[:-2]) or parts[0]}@{parts[-2]}")
    return libs


# Two configs per core, matching the default/size pair the ESP-IDF builds have.
FQBN_CONFIGS: dict[str, str] = {
    "arduino-default": "",
    # DebugLevel is the closest Arduino analogue of LOG_DEFAULT_LEVEL: it changes
    # what the log macros expand to, so it moves real code across the core.
    "arduino-verbose": "DebugLevel=verbose",
}


def build_arduino_corpus(
    core_version: str,
    chip: str = "esp32",
    fqbn: str | None = None,
    config_name: str = "arduino-default",
    libraries: tuple[str, ...] = POPULAR_LIBRARIES,
    cache_dir: Path | None = None,
    verbose: bool = False,
    rebuild_image: bool = False,
) -> BuildResult:
    """Compile the probe sketch for one core version and harvest its signatures."""
    import tempfile

    if chip != "esp32":
        raise CorpusBuildError(
            f"the Arduino path currently covers esp32 only, not {chip}",
            remedy="arduino-esp32 supports the S2/S3 variants and the probe sketch "
            "is chip-agnostic; the FQBN and the ROM/toolchain wiring for them are "
            "simply untested, so this refuses rather than producing signatures "
            "nobody has checked.",
        )

    tag = build_image(core_version, libraries, verbose=verbose, rebuild=rebuild_image)
    od_version = objdump_version(str(find_objdump(chip)))
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="espfw-arduino-") as tmp:
        out = Path(tmp)
        board = fqbn or f"esp32:esp32:{chip}"
        options = FQBN_CONFIGS.get(config_name, "")
        if options:
            board = f"{board}:{options}"
        argv = [
            "docker", "run", "--rm",
            "-v", f"{out}:/out",
            "-v", f"{ARDUINO_DIR / 'build.sh'}:/build.sh:ro",
            "-v", f"{ARDUINO_DIR / 'probe'}:/probe:ro",
            tag,
            "bash", "/build.sh", board,
        ]
        proc = subprocess.run(argv, capture_output=not verbose, text=True, check=False)
        if proc.returncode != 0:
            tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()[-30:]
            raise CorpusBuildError(
                f"the arduino-esp32 {core_version} build failed",
                remedy="Build output tail:\n  " + "\n  ".join(tail),
            )

        # The FQBN options *are* the config on the Arduino side: the core's
        # sdkconfig is a static file that does not change with them, so hashing it
        # alone gave both configs the same key and the second silently replaced
        # the first. Recording the options in the hashed config text is what makes
        # two Arduino configs two builds.
        resolved = out / "sdkconfig.out"
        existing = resolved.read_text() if resolved.is_file() else ""
        resolved.write_text(
            existing + f"\nESPFW_FQBN_OPTIONS={options or 'none'}\n"
        )

        version = f"{FRAMEWORK}@{core_version}"
        bundled = bundled_idf_version(out)
        libs = installed_libraries(out)

        result = _harvest_and_store(
            out=out,
            version=version,
            chip=chip,
            toolchain=_arduino_toolchain(out),
            od_version=od_version,
            config_name=config_name,
            image=tag,
            cache_dir=cache_dir,
            duration=time.monotonic() - started,
        )

    if bundled:
        result.warnings.append(
            f"this core bundles ESP-IDF {bundled}; an image built with it reports "
            f"{bundled} in its app descriptor, not {version}."
        )
    else:
        result.warnings.append(
            "the bundled ESP-IDF version could not be read from this core, so a "
            "descriptor naming it cannot be reconciled with the core version"
        )
    if libs:
        result.warnings.append(f"libraries compiled in: {', '.join(libs[:12])}")
    result.provenance = provenance.current(objdump_version=od_version)
    return result


def _arduino_toolchain(out: Path) -> str:
    """Identify the compiler that built this corpus."""
    marker = out / "objdump_version.txt"
    text = marker.read_text().strip() if marker.is_file() else ""
    m = re.search(r"\(([^)]*)\)\s*([0-9][\w.]*)", text)
    if not m:
        return text or "arduino-unknown"
    build = m.group(1).replace("crosstool-NG ", "").strip()
    return f"{build}/binutils-{m.group(2)}"


def config_hash_of(out: Path) -> str:
    """Arduino has no sdkconfig to hash, so the core's own sdkconfig stands in."""
    sdkconfig = out / "sdkconfig"
    return config_hash(sdkconfig.read_text() if sdkconfig.is_file() else "")
