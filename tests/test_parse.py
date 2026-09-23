"""Golden-file tests for `flash-info` across image types."""

from __future__ import annotations

import pytest

from espfw.errors import ParseError, UnsupportedTargetError
from espfw.parse import parse_file
from espfw.parse.models import InputKind
from tests import fixtures


@pytest.fixture
def write(tmp_path):
    def _write(name: str, data: bytes):
        p = tmp_path / name
        p.write_bytes(data)
        return p

    return _write


def test_flash_dump_classification(write):
    r = parse_file(write("dump.bin", fixtures.build_flash_dump()))
    assert r.input_kind is InputKind.FLASH_DUMP
    assert r.chip == "esp32"
    assert r.partition_table_offset == 0x8000
    assert [p.label for p in r.partitions] == ["nvs", "phy_init", "factory"]
    assert [p.subtype_name for p in r.partitions] == ["nvs", "phy", "factory"]


def test_bare_app_partition(write):
    r = parse_file(write("app.bin", fixtures.build_image()))
    assert r.input_kind is InputKind.APP_PARTITION
    assert len(r.images) == 1
    assert r.images[0].role == "app"


def test_load_addresses_and_regions_are_mandatory_output(write):
    r = parse_file(write("dump.bin", fixtures.build_flash_dump(chip="esp32s3")))
    img = r.images[r.selected_image]
    assert img.segments, "segments must be reported"
    for seg in img.segments:
        assert seg.load_addr > 0
        assert seg.region is not None, "every load address must resolve to a region"
    regions = {s.region for s in img.segments}
    assert "drom" in regions and "irom" in regions


def test_app_descriptor_is_parsed(write):
    r = parse_file(write("dump.bin", fixtures.build_flash_dump(idf_ver="v5.2.1")))
    desc = r.images[r.selected_image].app_desc
    assert desc is not None
    assert desc.idf_ver == "v5.2.1"
    assert desc.project_name == "hello_world"
    assert desc.magic_word == 0xABCD5432


def test_bootloader_is_parsed_separately(write):
    r = parse_file(write("dump.bin", fixtures.build_flash_dump()))
    roles = [i.role for i in r.images]
    assert "bootloader" in roles, "the bootloader is a separate build and must be reported"


def test_checksum_and_hash_validation(write):
    good = parse_file(write("good.bin", fixtures.build_image()))
    assert good.images[0].checksum_valid is True
    assert good.images[0].sha256_valid is True

    bad = parse_file(write("bad.bin", fixtures.build_image(corrupt_checksum=True)))
    assert bad.images[0].checksum_valid is False


def test_riscv_target_is_refused_not_analysed(write):
    """Exit clearly rather than producing garbage."""
    with pytest.raises(UnsupportedTargetError) as exc:
        parse_file(write("c3.bin", fixtures.build_flash_dump(chip="esp32c3")))
    assert "esp32c3" in str(exc.value)
    assert exc.value.exit_code == 3


def test_flash_dump_starting_at_0x1000_is_supported(write):
    data = fixtures.build_flash_dump()[0x1000:]
    r = parse_file(write("shifted.bin", data))

    assert r.input_kind is InputKind.FLASH_DUMP
    assert r.flash_base_offset == 0x1000
    assert r.partition_table_offset == 0x7000
    assert [i.role for i in r.images] == ["bootloader", "app"]
    img = r.images[r.selected_image]
    assert img.role == "app"
    assert img.file_offset == 0xF000
    assert img.partition_label == "factory"
    assert all(p.present_in_file for p in r.partitions)


def test_moved_partition_table_is_found_and_flagged(write):
    data = fixtures.build_flash_dump(table_offset=0x10000, partitions=[
        ("nvs", 1, 0x02, 0x11000, 0x6000),
        ("factory", 0, 0x00, 0x20000, 0x100000),
    ])
    r = parse_file(write("moved.bin", data))
    assert r.partition_table_offset == 0x10000
    assert any("not the conventional 0x8000" in w for w in r.warnings)


def test_differing_ota_slots_are_surfaced(write):
    data = fixtures.build_flash_dump(
        partitions=fixtures.OTA_PARTITIONS, slot_variants={"ota_1": "v4.4.6"}
    )
    r = parse_file(write("ota.bin", data))
    assert r.ota_slots_identical is False
    assert any("different images" in w for w in r.warnings)
    # The default selection must be deterministic and stated.
    assert r.images[r.selected_image].partition_label == "ota_0"


def test_explicit_slot_selection(write):
    data = fixtures.build_flash_dump(
        partitions=fixtures.OTA_PARTITIONS, slot_variants={"ota_1": "v4.4.6"}
    )
    p = write("ota.bin", data)
    r = parse_file(p, select_slot="ota_1")
    assert r.images[r.selected_image].partition_label == "ota_1"
    assert r.images[r.selected_image].app_desc.idf_ver == "v4.4.6"


def test_identical_ota_slots_are_not_flagged(write):
    data = fixtures.build_flash_dump(partitions=fixtures.OTA_PARTITIONS)
    r = parse_file(write("ota.bin", data))
    assert r.ota_slots_identical is True


def test_truncated_dump_reports_missing_partitions(write):
    data = fixtures.build_flash_dump(
        partitions=fixtures.OTA_PARTITIONS, truncate_at=0x108000
    )
    r = parse_file(write("trunc.bin", data))
    assert any("beyond the end of this dump" in w for w in r.warnings)
    labels = [i.partition_label for i in r.images if i.role == "app"]
    assert "ota_1" not in labels


def test_garbage_input_is_rejected_clearly(write):
    with pytest.raises(ParseError):
        parse_file(write("junk.bin", b"\x00" * 4096))


def test_mapped_elf_is_normalized_for_downstream_analysis(tmp_path):
    from espfw.elfwriter import write_program_elf

    path = write_program_elf(
        tmp_path / "app0.elf",
        [
            (".iram0.text", 0x40080000, b"\x36\x41\x00\x1d\xf0", True),
            (".dram0.data", 0x3FFB0000, b"data", False),
        ],
        entry=0x40080000,
    )
    result = parse_file(path)

    assert result.input_kind is InputKind.ELF
    assert result.selected_image == 0
    assert result.images[0].header.entry_addr == 0x40080000
    assert [(segment.load_addr, segment.executable) for segment in result.images[0].segments] == [
        (0x40080000, True),
        (0x3FFB0000, False),
    ]
