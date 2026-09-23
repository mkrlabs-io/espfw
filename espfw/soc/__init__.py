"""Per-chip facts: identity and address-space layout."""

from espfw.soc.chips import CHIPS, Arch, Chip, chip_by_id, region_for_address

__all__ = ["CHIPS", "Arch", "Chip", "chip_by_id", "region_for_address"]
