"""Structural normalization of an ambiguous input: flash dump, app image or ELF."""

from espfw.parse.models import (
    AppDescriptor,
    AppImage,
    ImageHeader,
    InputKind,
    ParseResult,
    Partition,
    Segment,
)
from espfw.parse.reader import parse_file

__all__ = [
    "AppDescriptor",
    "AppImage",
    "ImageHeader",
    "InputKind",
    "ParseResult",
    "Partition",
    "Segment",
    "parse_file",
]
