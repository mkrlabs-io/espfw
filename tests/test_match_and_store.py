"""Matcher and corpus store behaviour."""

from __future__ import annotations

import pytest

from espfw.canon.xtensa import canonicalize
from espfw.corpus.config import config_hash, normalize_config
from espfw.corpus.models import BuildKey
from espfw.corpus.store import open_store
from espfw.disasm.types import InsnClass, Instruction
from espfw.match import ExactMatcher, Query, Signature


def sig(name, digest, origin="archive", component="freertos"):
    return Signature(name=name, digest=digest, component=component, origin=origin)


def test_exact_match_identifies_by_digest():
    m = ExactMatcher([sig("vTaskDelay", "aaa"), sig("xQueueSend", "bbb")])
    hits = m.match([Query(key="f1", digest="aaa")])
    assert hits["f1"].name == "vTaskDelay"
    assert hits["f1"].confidence == 1.0
    assert hits["f1"].ambiguous_with == []


def test_unmatched_queries_are_absent_not_guessed():
    m = ExactMatcher([sig("vTaskDelay", "aaa")])
    assert m.match([Query(key="f1", digest="zzz")]) == {}


def test_shared_canonical_forms_are_reported_as_ambiguous():
    """Two functions with identical code cannot be told apart by exact matching.
    Reporting one name confidently would be a lie."""
    m = ExactMatcher([sig("xPortCheckValidListMem", "aaa"),
                      sig("xPortCheckValidTCBMem", "aaa")])
    hit = m.match([Query(key="f1", digest="aaa")])["f1"]
    assert hit.ambiguous_with, "the alternative identity must be surfaced"
    assert hit.confidence < 1.0
    assert {hit.name, *hit.ambiguous_with} == {
        "xPortCheckValidListMem", "xPortCheckValidTCBMem"
    }


def test_linked_signatures_are_preferred_over_archive_ones():
    """Firmware code has been through linker relaxation; so has the linked ELF.
    The archive copy has not, so it is the worse reference."""
    m = ExactMatcher([sig("f", "aaa", origin="archive"),
                      sig("f", "aaa", origin="linked")])
    assert m.match([Query(key="f1", digest="aaa")])["f1"].origin == "linked"


def test_config_normalization_ignores_comments_and_order():
    a = "# a comment\nCONFIG_X=y\n\nCONFIG_A=1\n"
    b = "CONFIG_A=1\nCONFIG_X=y\n# different comment\n"
    assert normalize_config(a) == normalize_config(b)
    assert config_hash(a) == config_hash(b)


def test_config_normalization_respects_real_differences():
    assert config_hash("CONFIG_X=y\n") != config_hash("CONFIG_X=n\n")


def _form():
    return canonicalize([
        Instruction(addr=0x100, size=3, raw=b"\x00\x00\x00", mnemonic="entry",
                    operands=["a1", "32"], cls=InsnClass.ENTRY),
        Instruction(addr=0x103, size=2, raw=b"\x00\x00", mnemonic="retw.n",
                    operands=[], cls=InsnClass.RETURN),
    ])


@pytest.fixture
def store(tmp_path):
    with open_store(tmp_path) as s:
        yield s


def test_store_roundtrip(store):
    key = BuildKey(idf_version="v5.4", config_hash="abc", chip="esp32", toolchain="gcc-14")
    bid = store.create_build(key, "default", "CONFIG_X=y", "objdump 2.43")
    store.add_functions(bid, [("vTaskDelay", "freertos", "tasks.c.obj", "archive", 0x100, _form())])
    store.commit()

    [found] = store.builds_for("v5.4", "esp32")
    assert found.key == key
    assert found.function_count == 1
    assert found.archive_functions == 1
    assert not found.stale


def test_a_build_is_only_found_for_its_own_version_and_chip(store):
    key = BuildKey(idf_version="v5.4", config_hash="abc", chip="esp32", toolchain="gcc-14")
    store.create_build(key, "default", None, None)
    store.commit()
    assert store.builds_for("v5.1", "esp32") == []
    assert store.builds_for("v5.4", "esp32s3") == []


def test_canonicalizer_change_makes_builds_stale_and_gc_removes_them(store, monkeypatch):
    key = BuildKey(idf_version="v5.4", config_hash="abc", chip="esp32", toolchain="gcc-14")
    bid = store.create_build(key, "default", None, None)
    store.add_functions(bid, [("f", "c", "o", "archive", 0x100, _form())])
    store.commit()

    import espfw.corpus.store as store_mod

    monkeypatch.setattr(store_mod, "CANON_VERSION", store_mod.CANON_VERSION + 1)

    listing = store.list_builds()
    assert listing.builds[0].stale
    assert any("not comparable" in w for w in listing.warnings)

    dry = store.gc(dry_run=True)
    assert dry.functions_removed == 1
    assert store.function_count(bid) == 1, "a dry run must not delete"

    real = store.gc()
    assert real.functions_removed == 1
    assert store.function_count(bid) == 0


def test_empty_corpus_explains_how_to_populate_it(store):
    listing = store.list_builds()
    assert listing.builds == []
    assert any("corpus build" in w for w in listing.warnings)


def test_same_name_in_two_components_reports_both():
    """IDF 5.5 ships the mbedTLS wrappers in both mbedcrypto and tfpsacrypto.
    The match is right; which archive supplied it is unknowable, and naming
    one of them alone would imply that archive is linked."""
    from espfw.corpus.models import CorpusSource

    def src(build_id):
        return CorpusSource(build_id=build_id, idf_version="v5.5", config_name="d",
                            config_hash="h", chip="esp32", toolchain="t",
                            canon_version=3, created_at="now")

    same_build = ExactMatcher([
        Signature(name="mbedtls_mpi_init", digest="aaa", component="mbedcrypto", source=src(1)),
        Signature(name="mbedtls_mpi_init", digest="aaa", component="tfpsacrypto", source=src(1)),
    ])
    hit = same_build.match([Query(key="f1", digest="aaa")])["f1"]
    assert hit.ambiguous_with == [], "same name is not name-ambiguity"
    assert {hit.component, *hit.shared_components} == {"mbedcrypto", "tfpsacrypto"}

    # A component renamed between IDF versions is not the same thing.
    renamed = ExactMatcher([
        Signature(name="esp_dport_access_reg_read", digest="bbb", component="soc", source=src(1)),
        Signature(name="esp_dport_access_reg_read", digest="bbb", component="esp_hw_support", source=src(2)),
    ])
    assert renamed.match([Query(key="f1", digest="bbb")])["f1"].shared_components == []
