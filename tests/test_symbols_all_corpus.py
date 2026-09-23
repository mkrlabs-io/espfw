"""All-corpus symbol lookup and source attribution."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from espfw.boundaries.models import FunctionBoundary, FunctionSet
from espfw.canon.xtensa import canonicalize
from espfw.corpus.models import BuildKey
from espfw.corpus.store import open_store
from espfw.disasm.types import InsnClass, Instruction
from espfw.errors import CorpusMissingError
from espfw.symbols import run as symbols_run


def _form():
    return canonicalize(
        [
            Instruction(
                addr=0x400D0000,
                size=3,
                raw=b"\x00\x00\x00",
                mnemonic="entry",
                operands=["a1", "32"],
                cls=InsnClass.ENTRY,
            ),
            Instruction(
                addr=0x400D0003,
                size=2,
                raw=b"\x00\x00",
                mnemonic="retw.n",
                operands=[],
                cls=InsnClass.RETURN,
            ),
        ]
    )


def _analysis(form, *, parse_warning=None, boundary_warning=None):
    functions = FunctionSet(
        path="app.bin",
        chip="esp32",
        recovery_version="1",
        functions=[
            FunctionBoundary(
                entry=0x400D0000,
                file_offset=0x20,
                size=form.size,
                ranges=[(0x400D0000, 0x400D0000 + form.size)],
            )
        ],
        warnings=[boundary_warning] if boundary_warning else [],
    )
    parsed_warnings = [parse_warning] if parse_warning else []
    return SimpleNamespace(
        parsed=SimpleNamespace(path="app.bin", warnings=parsed_warnings),
        chip="esp32",
        functions=functions,
        code_segments=[("irom", 0x400D0000, form.size)],
        forms={0x400D0000: form},
        warnings=[],
    )


def _add_build(store, version, form, *, name="vTaskDelay", chip="esp32"):
    key = BuildKey(
        idf_version=version,
        config_hash=f"hash-{version}-{chip}",
        chip=chip,
        toolchain="gcc-14",
    )
    build_id = store.create_build(key, "default", "CONFIG_X=y", "objdump test")
    store.add_functions(
        build_id,
        [(name, "freertos", "tasks.c.obj", "archive", 0x400D0000, form)],
    )
    return build_id


def _run(cache, analysis, monkeypatch):
    monkeypatch.setattr(symbols_run, "find_objdump", lambda _chip: Path("/fake/objdump"))
    monkeypatch.setattr(symbols_run, "objdump_version", lambda _path: "objdump test")
    return symbols_run.run_symbols(
        "app.bin", cache_dir=cache, analysis=analysis
    )


def test_omitted_version_searches_every_current_build_for_the_chip(
    tmp_path, monkeypatch, capsys
):
    form = _form()
    with open_store(tmp_path) as store:
        _add_build(store, "v4.4.8", form)
        _add_build(store, "v5.4", form)
        _add_build(store, "v5.4-s3", form, chip="esp32s3")
        stale = _add_build(store, "stale", form)
        store.conn.execute("UPDATE builds SET canon_version=0 WHERE id=?", (stale,))
        store.commit()

    result = _run(tmp_path, _analysis(form), monkeypatch)

    assert {source.idf_version for source in result.corpus_sources} == {"v4.4.8", "v5.4"}
    assert result.coverage.matched == result.coverage.total == 1
    match = result.identified[0]
    versions_by_id = {
        source.build_id: source.idf_version for source in result.corpus_sources
    }
    assert {versions_by_id[source_id] for source_id in match.corpus_source_ids} == {
        "v4.4.8", "v5.4"
    }
    assert not result.near_miss.available
    assert "All-corpus mode" in result.near_miss.reason

    from espfw.cli import _render_symbols

    _render_symbols(result)
    output = capsys.readouterr().out
    assert "0x400d0000" in output
    assert "vTaskDelay" in output
    assert "v4.4.8/default" in output and "v5.4/default" in output
    assert "corpus hits: 1 identified function(s)" in output
    assert "ambiguity: 1 unambiguous (100.0%), 0 ambiguous (0.0%)" in output
    assert "by component:" in output
    assert "freertos" in output
    assert "by version (2 of 2 contributed):" in output
    assert "by corpus source (2 of 2 searched build(s) contributed):" in output


def test_ambiguity_keeps_sources_for_the_selected_name(tmp_path, monkeypatch):
    form = _form()
    with open_store(tmp_path) as store:
        _add_build(store, "v4.4.8", form, name="xQueueSend")
        _add_build(store, "v5.4", form, name="vTaskDelay")
        store.commit()

    result = _run(tmp_path, _analysis(form), monkeypatch)
    match = result.identified[0]
    versions_by_id = {
        source.build_id: source.idf_version for source in result.corpus_sources
    }
    assert match.name == "vTaskDelay"
    assert match.ambiguous_with == ["xQueueSend"]
    assert [versions_by_id[source_id] for source_id in match.corpus_source_ids] == ["v5.4"]


def test_archive_and_linked_copy_report_one_source_match(tmp_path, monkeypatch):
    form = _form()
    with open_store(tmp_path) as store:
        build_id = _add_build(store, "v5.4", form)
        store.add_functions(
            build_id,
            [("vTaskDelay", "freertos", None, "linked", 0x400D0000, form)],
        )
        store.commit()

    result = _run(tmp_path, _analysis(form), monkeypatch)
    match = result.identified[0]
    assert len(match.corpus_source_ids) == 1
    assert match.origin == "linked"


def test_empty_all_corpus_mode_fails_without_building_anything(tmp_path):
    with pytest.raises(CorpusMissingError, match="no current corpus data") as exc:
        symbols_run.run_symbols(
            "app.bin", cache_dir=tmp_path, analysis=_analysis(_form())
        )
    assert "--from-artifacts" in (exc.value.remedy or "")


def test_symbols_result_surfaces_parse_and_boundary_warnings(
    tmp_path, monkeypatch
):
    form = _form()
    with open_store(tmp_path) as store:
        _add_build(store, "v5.4", form)
        store.commit()

    analysis = _analysis(
        form,
        parse_warning="parse warning",
        boundary_warning="boundary warning",
    )
    result = _run(tmp_path, analysis, monkeypatch)

    assert "parse warning" in result.warnings
    assert "boundary warning" in result.warnings


def _ident(vaddr, component, *, ambiguous=False):
    from espfw.symbols.models import IdentifiedFunction

    return IdentifiedFunction(
        offset=None, vaddr=vaddr, size=32, name=f"f_{vaddr:x}", component=component,
        ambiguous_with=["other"] if ambiguous else [],
    )


def _unident(vaddr):
    from espfw.symbols.models import UnidentifiedFunction

    return UnidentifiedFunction(offset=None, vaddr=vaddr, size=32)


def test_layout_labels_a_gap_between_two_matches_of_one_component():
    """Code is laid out in link order, so an unmatched function between two
    lwip functions is lwip: SDK code that did not match, not application."""
    from espfw.symbols.run import _layout

    gap = _unident(0x120)
    regions = _layout([_ident(0x100, "lwip"), _ident(0x140, "lwip")], [gap])
    assert gap.likely_component == "lwip"
    assert [(r.component, r.functions, r.inferred) for r in regions] == [("lwip", 3, 1)]


def test_layout_leaves_a_gap_between_different_components_unclaimed():
    from espfw.symbols.run import _layout

    gap = _unident(0x120)
    regions = _layout([_ident(0x100, "lwip"), _ident(0x140, "nvs_flash")], [gap])
    assert gap.likely_component is None
    assert [r.component for r in regions] == ["lwip", None, "nvs_flash"]


def test_ambiguous_matches_do_not_anchor_a_region():
    """An ambiguous name is one of several components' identical functions;
    letting it label neighbours put Arduino components into a pure IDF image."""
    from espfw.symbols.run import _layout

    gap = _unident(0x120)
    regions = _layout(
        [_ident(0x100, "lwip"), _ident(0x140, "core", ambiguous=True), _ident(0x160, "lwip")],
        [gap],
    )
    assert gap.likely_component == "lwip"
    assert [r.component for r in regions] == ["lwip"]
    assert regions[0].functions == 4 and regions[0].inferred == 2


def test_tiny_matches_do_not_anchor_a_region():
    """A 13-byte getter has the same form as every other getter, including the
    application's, which the corpus cannot know about. Measured: tiny anchors
    planted lwip flags inside the application and split it in two."""
    from espfw.symbols.models import IdentifiedFunction
    from espfw.symbols.run import _layout

    tiny = IdentifiedFunction(offset=None, vaddr=0x120, size=13, name="esp_sntp_enabled", component="lwip")
    gap_a, gap_b = _unident(0x100), _unident(0x140)
    regions = _layout([tiny], [gap_a, gap_b])
    assert [r.component for r in regions] == [None]
    assert gap_a.likely_component is None and gap_b.likely_component is None


def test_a_function_shared_by_two_components_does_not_anchor_a_region():
    from espfw.symbols.models import IdentifiedFunction
    from espfw.symbols.run import _layout

    shared = IdentifiedFunction(
        offset=None, vaddr=0x120, size=90, name="mbedtls_ecdsa_sign_det_ext",
        component="mbedcrypto", shared_components=["tfpsacrypto"],
    )
    gap = _unident(0x100)
    regions = _layout([shared], [gap])
    assert [r.component for r in regions] == [None]
