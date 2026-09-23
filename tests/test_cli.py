"""Focused dependency-free CLI surface."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from espfw.cli import _parser, main
from tests import fixtures


def test_root_help_contains_only_the_focused_commands():
    help_text = _parser().format_help()
    for command in ("flash-info", "elf", "symbols", "corpus"):
        assert command in help_text
    for removed in ("idf-version", "sdkconfig", "triage", "diff", "functions"):
        assert f"    {removed}" not in help_text


def test_symbols_needs_only_an_image_argument():
    args = _parser().parse_args(["symbols", "app0.bin"])
    assert args.image == Path("app0.bin")
    assert not hasattr(args, "version")


def test_flash_info_runs_through_the_stdlib_cli(tmp_path, capsys):
    image = tmp_path / "flash.bin"
    image.write_bytes(fixtures.build_flash_dump())

    main(["flash-info", str(image)])

    output = capsys.readouterr().out
    assert "flash_dump" in output
    assert "chip       : esp32" in output
    assert "factory" in output


def test_elf_cli_writes_a_mapped_file(tmp_path, capsys):
    image = tmp_path / "app0.bin"
    image.write_bytes(fixtures.build_image())
    output = tmp_path / "app0.elf"

    main(["elf", str(image), str(output)])

    assert output.read_bytes().startswith(b"\x7fELF")
    assert "entry" in capsys.readouterr().out


def test_cli_imports_without_site_packages():
    completed = subprocess.run(
        [sys.executable, "-S", "-m", "espfw", "--help"],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "flash-info" in completed.stdout
