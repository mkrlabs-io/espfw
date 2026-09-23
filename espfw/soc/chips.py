"""Chip identity and address-space layout.

Values transcribed from `components/soc/<chip>/include/soc/soc.h` and the
`esp_chip_id_t` enum in `components/bootloader_support/include/esp_app_format.h`
of esp-idf. Region bounds are what turn a segment's load address into a
meaningful name, and what tells the disassembler whether a call target lies
outside every loaded segment (i.e. is a ROM call).
"""

from __future__ import annotations

from enum import StrEnum

from espfw.schema import BaseModel, Field


class Arch(StrEnum):
    XTENSA = "xtensa"
    RISCV = "riscv"


class Region(BaseModel):
    """A named span of the physical address space."""

    name: str
    low: int
    high: int
    executable: bool = False

    def contains(self, addr: int) -> bool:
        return self.low <= addr < self.high

    @property
    def size(self) -> int:
        return self.high - self.low


class Chip(BaseModel):
    """One ESP32-family part."""

    name: str
    chip_id: int
    arch: Arch
    regions: list[Region] = Field(default_factory=list)
    toolchain_prefix: str | None = None
    """Xtensa binutils prefix, e.g. 'xtensa-esp32s3-elf'. None for RISC-V parts,
    which are refused rather than analysed."""
    """Basename stem in esp-rom-elfs, e.g. 'esp32s3' -> 'esp32s3_rev0_rom.elf'."""

    @property
    def supported(self) -> bool:
        return self.arch is Arch.XTENSA


def _r(name: str, low: int, high: int, executable: bool = False) -> Region:
    return Region(name=name, low=low, high=high, executable=executable)


# --- Xtensa parts: supported ------------------------------------------------

ESP32 = Chip(
    name="esp32",
    chip_id=0x0000,
    arch=Arch.XTENSA,
    toolchain_prefix="xtensa-esp32-elf",
    regions=[
        _r("drom", 0x3F400000, 0x3F800000),
        _r("extram_data", 0x3F800000, 0x3FC00000),
        _r("rtc_dram", 0x3FF80000, 0x3FF82000),
        _r("dram", 0x3FFAE000, 0x40000000),
        _r("diram_dram", 0x3FFE0000, 0x40000000),
        _r("irom_mask", 0x40000000, 0x40070000, executable=True),
        _r("cache_pro", 0x40070000, 0x40078000),
        _r("cache_app", 0x40078000, 0x40080000),
        _r("iram", 0x40080000, 0x400AA000, executable=True),
        _r("diram_iram", 0x400A0000, 0x400C0000, executable=True),
        _r("rtc_iram", 0x400C0000, 0x400C2000, executable=True),
        _r("irom", 0x400D0000, 0x40400000, executable=True),
        _r("rtc_data", 0x50000000, 0x50002000),
    ],
)

ESP32S2 = Chip(
    name="esp32s2",
    chip_id=0x0002,
    arch=Arch.XTENSA,
    toolchain_prefix="xtensa-esp32s2-elf",
    regions=[
        _r("drom", 0x3F000000, 0x3FF80000),
        _r("extram_data", 0x3F500000, 0x3FF80000),
        _r("rtc_dram", 0x3FF9E000, 0x3FFA0000),
        _r("dram", 0x3FFB0000, 0x40000000),
        _r("diram_dram", 0x3FFB0000, 0x40000000),
        _r("irom_mask", 0x40000000, 0x40020000, executable=True),
        _r("iram", 0x40020000, 0x40070000, executable=True),
        _r("diram_iram", 0x40020000, 0x40070000, executable=True),
        _r("rtc_iram", 0x40070000, 0x40072000, executable=True),
        _r("irom", 0x40080000, 0x40800000, executable=True),
        _r("rtc_data", 0x50000000, 0x50002000),
    ],
)

ESP32S3 = Chip(
    name="esp32s3",
    chip_id=0x0009,
    arch=Arch.XTENSA,
    toolchain_prefix="xtensa-esp32s3-elf",
    regions=[
        _r("drom", 0x3C000000, 0x3E000000),
        _r("extram_data", 0x3C000000, 0x3E000000),
        _r("dram", 0x3FC88000, 0x3FD00000),
        _r("diram_dram", 0x3FC88000, 0x3FCF0000),
        _r("irom_mask", 0x40000000, 0x40060000, executable=True),
        _r("iram", 0x40370000, 0x403E0000, executable=True),
        _r("diram_iram", 0x40378000, 0x403E0000, executable=True),
        _r("irom", 0x42000000, 0x44000000, executable=True),
        _r("rtc_data", 0x50000000, 0x50002000),
        _r("rtc_iram", 0x600FE000, 0x60100000, executable=True),
    ],
)

# --- RISC-V parts: recognised only so we can refuse them precisely -------

_RISCV = [
    ("esp32c3", 0x0005),
    ("esp32c2", 0x000C),
    ("esp32c6", 0x000D),
    ("esp32h2", 0x0010),
    ("esp32p4", 0x0012),
    ("esp32c5", 0x0017),
]

CHIPS: dict[str, Chip] = {c.name: c for c in (ESP32, ESP32S2, ESP32S3)}
for _name, _id in _RISCV:
    CHIPS[_name] = Chip(name=_name, chip_id=_id, arch=Arch.RISCV)

_BY_ID: dict[int, Chip] = {c.chip_id: c for c in CHIPS.values()}


def chip_by_id(chip_id: int) -> Chip | None:
    """Map an `esp_image_header_t.chip_id` value to a chip, or None if unknown.

    Note that ESP32 is id 0, and images predating the chip_id field carry zero
    in those bytes — which happens to give the right answer, but means id 0 is
    weaker evidence than a nonzero id. Callers that care corroborate with the
    segment load addresses.
    """
    return _BY_ID.get(chip_id)


def region_for_address(chip: Chip, addr: int) -> Region | None:
    """Name the region an address falls in, preferring the most specific match.

    Several regions overlap by design (diram is a window onto dram/iram;
    extram overlaps drom on S2/S3), so ties are broken by taking the smallest
    containing span rather than declaration order.
    """
    hits = [r for r in chip.regions if r.contains(addr)]
    if not hits:
        return None
    return min(hits, key=lambda r: r.size)
