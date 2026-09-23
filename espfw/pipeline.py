"""Shared parse, boundary recovery, decoding, and canonicalization pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from espfw.boundaries import recover_functions
from espfw.boundaries.models import FunctionSet
from espfw.boundaries.run import decode_boundaries
from espfw.canon.xtensa import CanonicalForm, canonicalize
from espfw.errors import ParseError
from espfw.parse import parse_file
from espfw.parse.models import ParseResult
from espfw.strings import cstr_at


@dataclass(slots=True)
class ImageAnalysis:
    parsed: ParseResult
    chip: str
    functions: FunctionSet
    code_segments: list[tuple[str, int, int]] = field(default_factory=list)
    """(region, load address, length) of every executable segment."""
    forms: dict[int, CanonicalForm] = field(default_factory=dict)
    """entry vaddr -> canonical form. Keyed on the entry rather than the name
    because a stripped image has no names; that is the whole problem."""

    @property
    def warnings(self) -> list[str]:
        return [*self.parsed.warnings, *self.functions.warnings]


def analyze_image(
    image_path: str | Path,
    slot: str | None = None,
    cache_dir: Path | None = None,
    refresh: bool = False,
) -> ImageAnalysis:
    parsed = parse_file(image_path, select_slot=slot)
    if parsed.chip is None:
        raise ParseError(
            "the chip variant could not be determined, and every step below this "
            "depends on it",
            remedy="`flash-info` reports the chip candidates and the evidence for each: "
            f"run `espfw flash-info {image_path}` to see why none was conclusive.",
        )

    functions = recover_functions(
        image_path, slot=slot, cache_dir=cache_dir, refresh=refresh
    )
    img = parsed.images[parsed.selected_image or 0]
    data = Path(parsed.path).read_bytes()

    decoded = decode_boundaries(parsed.chip, functions.functions, img, data)
    read_cstr = _image_cstr_reader(img, data)
    forms = {
        fn.entry: canonicalize(
            decoded[fn.entry], base_addr=fn.entry, read_cstr=read_cstr
        )
        for fn in functions.functions
        if decoded.get(fn.entry)
    }

    return ImageAnalysis(
        parsed=parsed,
        chip=parsed.chip,
        functions=functions,
        code_segments=[
            (seg.region or "code", seg.load_addr, seg.length)
            for seg in img.segments
            if seg.executable and seg.length
        ],
        forms=forms,
    )


def _image_cstr_reader(img, data: bytes):
    """Resolve a literal to the string it points at, from the image's segments.

    Non-executable segments only, for the same reason the corpus side excludes
    text: printable bytes inside code are not strings.
    """
    regions = [
        (seg.load_addr, data[seg.file_offset : seg.file_offset + seg.length])
        for seg in img.segments
        if not seg.executable and seg.length
    ]

    def read(addr: int) -> str | None:
        for base, blob in regions:
            if base <= addr < base + len(blob):
                return cstr_at(blob, addr - base)
        return None

    return read
