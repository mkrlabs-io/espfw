"""Exception types that map onto distinct CLI exit codes.

Every error the user can plausibly hit should carry a remedy: the spec is
explicit that a missing corpus entry must print the exact ``corpus build``
command rather than silently doing anything.
"""

from __future__ import annotations


class EspfwError(Exception):
    """Base for all espfw errors. Carries an optional remedy line."""

    exit_code = 1

    def __init__(self, message: str, remedy: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy


class UnsupportedTargetError(EspfwError):
    """A RISC-V Espressif target, or anything else espfw does not analyse."""

    exit_code = 3


class ParseError(EspfwError):
    """The image could not be interpreted as an Espressif artifact."""

    exit_code = 4


class ToolchainError(EspfwError):
    """A required external tool (objdump, Docker) is missing or broken."""

    exit_code = 5


class CorpusMissingError(EspfwError):
    """The requested (version, config, chip, toolchain) is not cached."""

    exit_code = 6


class CorpusBuildError(EspfwError):
    """A corpus build failed."""

    exit_code = 7
