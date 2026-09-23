# Commands

Global options may appear before or after the selected command:

- `--json`: compact JSON envelope on stdout
- `-o, --output FILE`: complete indented JSON in a file
- `--cache-dir DIR`: override corpus and boundary cache root

## `flash-info IMAGE [--slot LABEL]`

Print partition, chip, app descriptor, checksum, segment offset, and load-address
details from a flash dump, app image, or ELF.

## `elf IMAGE OUT [--slot LABEL]`

Write an address-correct, symbol-free ELF32 Xtensa file suitable for Ghidra.

## `symbols IMAGE [--slot LABEL]`

Recover functions and exact-match them against all current corpus builds for the
detected chip. No version/config argument is required. Output includes virtual
address, input file offset, symbol name, ambiguity, and concrete corpus sources.

## Corpus

- `corpus list [--version VERSION]`
- `corpus build --version VERSION [--config PRESET|FILE] [--chip CHIP]`
- `corpus build --version VERSION --from-artifacts DIR [--chip CHIP]`
- `corpus build-arduino (--core VERSION | --popular) [--chip CHIP]`
- `corpus rm --version VERSION [--config-hash PREFIX] [--chip CHIP] [--yes]`
- `corpus gc [--dry-run]`

The three build operations can invoke Docker. They are explicit and must not be
run without user approval.
