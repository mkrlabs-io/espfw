"""Canonicalization, versioned independently of the tool.

CANON_VERSION must be incremented on *any* change to canonical-form output.
Every signature and every analysis result carries it, so that when the rules
change, prior results are identifiable as stale rather than silently compared
against forms that were computed under different rules.
"""

from espfw.canon.xtensa import canonicalize

__all__ = ["CANON_VERSION", "canonicalize"]

CANON_VERSION = 3
# v2: strip trailing inter-function alignment padding before canonicalizing.
#     Symbol sizes include it and recovered boundaries do not, so without this
#     a function harvested from a symbol table never matches the same function
#     recovered from an image.
# v3: absorb the transformations the *linker* applies, so that a function
#     harvested from a `.a` archive canonicalizes the same as the same function
#     linked into an image: density-encoding choice, the `or aX,aY,aY` move
#     idiom, alignment padding, and the -mlongcalls `l32r`+`callx` sequence that
#     relaxation rewrites into a direct call. Measured on a blind wifi/scan
#     image against the v5.4 corpus: 1,257 -> 1,701 functions matched (+35%),
#     1,167 -> 1,510 of them unambiguous, with distinct corpus forms falling
#     only 15,705 -> 15,568 — so the recall is not bought by blurring functions
#     together.
