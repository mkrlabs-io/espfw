# espfw implementation specification

This file is the implementation source of truth for the focused `espfw` tool.

## 1. Scope

The public command surface is intentionally small:

```text
espfw flash-info IMAGE [--slot LABEL]
espfw elf IMAGE OUT [--slot LABEL]
espfw symbols IMAGE [--slot LABEL]
espfw corpus <subcommand>
```

`--version` at the root prints the tool version. The former `idf-version`,
`sdkconfig`, `triage`, `diff`, and `functions` commands are not public commands.
Boundary recovery remains an internal part of `symbols`.

The supported architectures are Xtensa ESP32, ESP32-S2, and ESP32-S3. Known
RISC-V Espressif targets must fail explicitly.

## 2. Dependency Boundary

The analyzer must import and run with the Python standard library alone.

- `flash-info` needs no external executable.
- `elf` needs no external executable.
- `symbols` may invoke an Espressif Xtensa `objdump`.
- SQLite is provided by the Python standard library.
- Ghidra must never be invoked by the analyzer.
- Docker may only be invoked by an explicit corpus build command.

No analysis command may implicitly build, download, or modify corpus entries.

## 3. Shared Output

Human output is plain text. `--json` emits:

```json
{"command": "...", "provenance": {}, "warnings": [], "result": {}}
```

`-o/--output FILE` writes the complete indented envelope. Models are stdlib
dataclasses with deterministic conversion of enums, nested models, and computed
address fields.

Errors use command-specific exit codes and include a remedy when the user can
act on the failure. Firmware strings and names are untrusted data.

## 4. `flash-info`

Input can be a full flash dump, a bare Espressif app image, or an ELF32 Xtensa
file. The result must retain:

- input kind, size, and SHA-256
- chip evidence
- partition table and partition bounds
- all recognized bootloader/app images
- deterministic selected application image
- app image header and descriptor where present
- checksum/hash status
- every segment's input file offset, load address, size, region, and executable
  status

For a flash dump, `--slot` selects by partition label. Without it, factory is
preferred, then `ota_0`, then the first app partition. Differing OTA slots are a
warning.

Partition entries carry absolute flash addresses. When a dump omits the leading
flash sectors, espfw infers the flash base from the shifted partition table and
app images and reports it as `flash base`.

ELF allocatable sections with bytes are normalized into one synthetic app image
so the same internal analysis path can consume `.bin` and mapped `.elf` inputs.
Header-only fields are marked unknown rather than invented.

## 5. `elf`

`elf IMAGE OUT` writes an ELF32 Xtensa executable from the selected app image.

- Section virtual addresses equal image segment load addresses.
- Executable permissions follow the segment memory region.
- Section names follow ESP-IDF linker conventions and remain unique.
- The ELF entry point equals the image entry point.
- Segment bytes are copied exactly.
- No inferred symbol table is emitted.

An address reported by `symbols` must land in the corresponding output section.

## 6. `symbols`

`symbols` takes only an image and optional slot. It does not require or infer a
version/config hypothesis.

### 6.1 Recovery

Function boundaries are recovered in-tool by recursive descent over Espressif
Xtensa `objdump` output. Literal pools must not be linearly decoded as code.
Each boundary retains entry address, source file offset, extent, reached ranges,
call edges, origin evidence, and confidence.

### 6.2 Canonical Form

Recovered functions and corpus functions use the same canonicalizer version.
Direct address operands, relocatable calls, and literal locations are normalized
according to the canonicalizer contract. Stale corpus forms are incomparable.

### 6.3 Corpus Selection

The search set is every build satisfying all of:

- `builds.chip` equals the detected chip
- `builds.canon_version` equals the running canonicalizer

It spans all cached versions, configs, and toolchains. Stale builds and builds
for another chip must not participate.

The store should query only target digests rather than load all canonical/raw
texts from a multi-version corpus into memory.

### 6.4 Exact Matching and Attribution

A target matches when its canonical digest equals a corpus function digest.
One target function contributes at most one item to coverage, regardless of how
many corpus rows match it.

Each identification reports:

- target virtual address and input file offset
- preferred name, component, origin, and confidence
- every alternative name sharing the canonical form
- every source build containing the preferred name with that matching form

A source build includes build ID, framework/version string, config name and
hash, chip, toolchain, canonicalizer version, and creation time. Per-function
build IDs resolve through the top-level source list, so build metadata is emitted
once rather than repeated for every function. Source ordering is deterministic.

Name ambiguity and source multiplicity are separate facts. A digest found under
the same name in ten builds is not name-ambiguous; it has ten source IDs. Other
names sharing the form remain in `ambiguous_with`.

### 6.5 Safety

All-corpus mode is exact-only. No near-miss or modified-function tier is
implemented. The result explicitly states that modified-function detection did
not run.

## 7. Corpus

The canonical corpus remains SQLite at:

```text
${ESPFW_CACHE_DIR:-${XDG_CACHE_HOME:-~/.cache}/espfw}/corpus.sqlite
```

A build key includes version, config hash, chip, toolchain, and canonicalizer
version. Databases written by earlier versions of the tool remain readable.

Supported management commands remain:

- `corpus build`: Docker-backed ESP-IDF build, or local ingestion with
  `--from-artifacts`
- `corpus build-arduino`: explicit Docker-backed Arduino build
- `corpus list`: inspect cached builds
- `corpus rm`: remove one selected build
- `corpus gc`: remove canonicalizer-stale data

Only corpus commands may write signatures. Corpus generation is always explicit.

## 8. Verification

Tests must cover:

- flash/app/ELF classification, slot selection, and RISC-V rejection
- byte-for-byte ELF mapping and absence of inferred symbols
- all-current-build selection and exclusion of stale/other-chip data
- per-hit name-to-source attribution and deterministic ambiguity
- empty-corpus failure without implicit generation
- command help containing only the focused top-level surface
- import and help execution under `python -S`
- compatibility with the existing SQLite corpus schema
