"""End-to-end tests against a real self-built firmware image.

The pipeline can mint its own labelled ground truth, which is the whole reason
these tests can exist: the linked ELF's symbol table says exactly what every
address is, and the .bin built beside it is what the tool analyses blind.

Requires a build tree in the layout `espfw corpus build` produces:

    export ESPFW_TEST_ARTIFACTS=/path/to/build-out
    espfw corpus build --version v5.4 --chip esp32 --from-artifacts $ESPFW_TEST_ARTIFACTS

Skipped entirely when that is not set, since producing it needs Docker and
several minutes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from espfw import elfreader
from espfw.boundaries import recover_functions
from espfw.corpus.build import harvest_artifacts
from espfw.symbols.run import run_symbols

ARTIFACTS = os.environ.get("ESPFW_TEST_ARTIFACTS")

pytestmark = pytest.mark.skipif(
    not ARTIFACTS or not Path(ARTIFACTS).is_dir(),
    reason="set ESPFW_TEST_ARTIFACTS to a corpus build tree to run integration tests",
)

VERSION = os.environ.get("ESPFW_TEST_IDF_VERSION", "v5.4")
CHIP = os.environ.get("ESPFW_TEST_CHIP", "esp32")


@pytest.fixture(scope="module")
def artifacts() -> Path:
    return Path(ARTIFACTS)


@pytest.fixture(scope="module")
def firmware(artifacts) -> Path:
    candidates = sorted((artifacts / "app").glob("*.bin"))
    binaries = [p for p in candidates if "bootloader" not in p.name]
    if not binaries:
        pytest.skip("no application .bin in the artifacts tree")
    return binaries[0]


@pytest.fixture(scope="module")
def ground_truth(artifacts) -> dict[int, str]:
    """address -> symbol name, from the linked ELF built alongside the image."""
    elfs = [p for p in sorted((artifacts / "app").glob("*.elf")) if "bootloader" not in p.name]
    if not elfs:
        pytest.skip("no application .elf in the artifacts tree")
    elf = elfreader.load(elfs[0])
    return {s.value: s.name for s in elf.functions()}


@pytest.fixture(scope="module")
def cache(tmp_path_factory) -> Path:
    """An isolated corpus, so these tests never read the user's real cache."""
    root = tmp_path_factory.mktemp("espfw-corpus")
    harvest_artifacts(Path(ARTIFACTS), version=VERSION, chip=CHIP, cache_dir=root)
    return root


@pytest.fixture(scope="module")
def result(firmware, cache):
    return run_symbols(firmware, cache_dir=cache)


def test_boundary_recovery_precision(firmware, ground_truth, cache):
    """Recovered entry points should land on real functions."""
    fs = recover_functions(firmware, cache_dir=cache)
    entries = {f.entry for f in fs.functions}
    real = entries & set(ground_truth)
    assert len(entries) > 100
    assert len(real) / len(entries) > 0.95, "boundary precision regressed"


def test_round_trip_recovers_most_of_the_sdk(result):
    """M4's acceptance criterion: build a known image, analyse it blind."""
    assert result.coverage.total > 100
    assert result.coverage.ratio > 0.90, (
        f"match rate {result.coverage.ratio:.1%} — a drop here usually means the "
        "canonicalizer or boundary spanning changed, not the firmware"
    )


def test_false_positive_floor_no_misidentifications(result, ground_truth):
    """Every name the tool asserts must be the right one.

    A wrong name is worse than no name — it stops an analyst looking.
    """
    wrong = []
    for f in result.identified:
        truth = ground_truth.get(f.vaddr)
        if truth is None:
            continue
        if truth != f.name and truth not in f.ambiguous_with:
            wrong.append((hex(f.vaddr), f.name, truth))
    assert not wrong, f"misidentified functions: {wrong[:10]}"


def test_every_identification_has_ground_truth(result, ground_truth):
    """An identification at an address with no symbol would mean the boundary
    was invented, and the name attached to nothing real."""
    orphans = [f for f in result.identified if f.vaddr not in ground_truth]
    assert not orphans, f"{len(orphans)} identifications at addresses with no symbol"


def test_unidentified_are_ranked_by_size_then_in_degree(result):
    sizes = [(-u.size, -u.in_degree) for u in result.unidentified]
    assert sizes == sorted(sizes), "ranking approximates 'most likely interesting'"


def test_provenance_records_what_produced_the_result(result):
    from espfw.canon import CANON_VERSION

    prov = result.provenance
    assert prov is not None
    assert prov.canonicalizer_version == CANON_VERSION
    assert prov.objdump_version and "objdump" in prov.objdump_version.lower()
    assert prov.corpus_revision


def test_synthetic_patch_is_no_longer_exactly_identified(
    firmware, cache, result, tmp_path
):
    """Whatever else happens, a patched function must stop being reported as a
    clean exact SDK match. Silently keeping the identity is the dangerous
    failure."""
    target = next(
        (f for f in result.identified if f.offset and f.size > 64), None
    )
    assert target is not None, "no suitable function to patch"

    data = bytearray(firmware.read_bytes())
    # Flip bytes in the middle of the body, well clear of the prologue so the
    # boundary is still recovered and the change is a body change.
    patch_at = target.offset + 16
    for i in range(patch_at, patch_at + 6):
        data[i] ^= 0xFF

    patched = tmp_path / "patched.bin"
    patched.write_bytes(bytes(data))

    after = run_symbols(patched, cache_dir=cache)
    still = {f.vaddr for f in after.identified}
    assert target.vaddr not in still, (
        f"{target.name} was patched but is still reported as an exact SDK match"
    )
    # The rest of the image must be unaffected: a patch is local evidence.
    assert after.coverage.matched >= result.coverage.matched - 5
