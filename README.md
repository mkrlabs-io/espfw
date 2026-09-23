# espfw

`espfw` analyses ESP32 firmware from the shipped binary, with no build tree, map
file, or `sdkconfig`. It parses a raw flash dump into an address-correct ELF for
a disassembler, then identifies which functions come from the ESP-IDF or Arduino
SDK by matching them against a local corpus of reference builds.

What the corpus recognises is SDK code. What is left over is the firmware's own
code, which is usually what an analyst wants to read. Because every match records
the exact reference build it came from, the same pass narrows the ESP-IDF version
the image was built against, working from bytes alone.

A worked example on a real co-processor image is written up on the MKR Labs blog,
[Reading a Stripped ESP32 Firmware with espfw](https://mkrlabs.io/research/reading-esp32-firmware-with-espfw).

## What it does

| command | purpose |
|---|---|
| `flash-info` | parse the partition table, app images, headers, checksums, and segment map |
| `elf` | write an address-correct, Ghidra-loadable ELF from a flash dump |
| `symbols` | match recovered functions against every compatible corpus build and show the version each came from |
| `corpus` | build, import, and manage the local signature corpus |

Supported targets are Xtensa ESP32, ESP32-S2, and ESP32-S3. RISC-V Espressif
targets are rejected rather than decoded as Xtensa.

## Quick start with Docker

The fastest way to run `symbols` is the published image, which bundles `espfw`,
the Espressif Xtensa `objdump`, and the same prebuilt corpus used in the article.
Nothing else is installed on the host.

```sh
docker run --rm -v "$PWD:/work" -w /work mkrlabs/espfw \
  symbols network_adapter_esp32.bin
```

The image is on Docker Hub at [`mkrlabs/espfw`](https://hub.docker.com/r/mkrlabs/espfw).
Inside it, the corpus lives at `/opt/espfw/cache/corpus.sqlite`
(`ESPFW_CACHE_DIR=/opt/espfw/cache`), so `symbols` finds it with no configuration.
`flash-info` and `elf` run the same way.

To reuse the bundled corpus with a locally installed `espfw`, copy it into the
default cache once:

```sh
id=$(docker create mkrlabs/espfw)
mkdir -p ~/.cache/espfw
docker cp "$id:/opt/espfw/cache/corpus.sqlite" ~/.cache/espfw/corpus.sqlite
docker rm "$id"
```

The bundled corpus covers the ESP32 target across ESP-IDF v3.3 through v6.1 and
the Arduino-ESP32 cores, in the `default` and `size` presets. `espfw corpus list`
prints exactly which builds are present.

### Building the image

The repository ships a `Dockerfile` that produces this image. Because the corpus
lives outside the repository, it is passed as a named build context rather than
copied in, and the toolchain is pinned to the objdump build the corpus was
disassembled with.

```sh
docker build \
  --build-context corpus="$HOME/.cache/espfw" \
  -t mkrlabs/espfw:latest .

# multi-arch, built and pushed in one step
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-context corpus="$HOME/.cache/espfw" \
  -t mkrlabs/espfw:latest --push .
```

## Install

For a local install you will need Python 3.11+, the Espressif Xtensa `objdump`,
and, only for building your own corpus entries, Docker. If you use the published
corpus you do not need Docker.

If you only run selected commands, the dependencies are narrower:

| command | needs |
|---|---|
| `flash-info`, `elf` | Python 3.11+ |
| `symbols` | Python 3.11+, the Espressif Xtensa `objdump`, and a populated corpus |
| `corpus build`, `corpus build-arduino` | the above, plus Docker |

The Python side has no third-party packages. It is the standard library only,
which is why the first two commands run from a bare checkout. `symbols` is not
standalone. Every instruction `espfw` reads is decoded by Espressif's own
binutils (`xtensa-esp32-elf-objdump` and the S2/S3 variants), deliberately, so
that the corpus and the firmware are disassembled by the same decoder and a
decoding difference can never masquerade as a different function. The toolchain
comes from the ESP-IDF tools installer. `espfw` finds it under
`~/.espressif/tools`, or where `ESPFW_TOOLCHAIN_DIR` / `ESPFW_OBJDUMP_<CHIP>`
point. The corpus is built from Espressif's Docker images and is never generated
as a side effect of analysis.

Ghidra is not invoked by `espfw`.

Install it as a command:

```sh
uv tool install .            # or: uv tool install --editable .  (for hacking on it)
espfw --help
```

`pipx install .` does the same without uv. Because the Python side needs nothing
but the standard library, it also runs straight from a checkout with no
environment at all: `python -m espfw --help`. The examples below assume the
installed command; `uv run espfw` works identically inside the checkout.

## Commands

### Inspect a flash dump

```sh
espfw flash-info flash.bin
espfw flash-info flash.bin --slot ota_1
```

This reports the partition table, app images, selected slot, chip, image header,
app descriptor, checksums, segment file offsets, load addresses, and memory
regions. It also accepts a bare app partition or an ELF, and detects flash dumps
that start at a nonzero flash address.

```text
network_adapter_esp32.bin  993,248 bytes  sha256:c0f05a4b06e4ed92...
input kind : app_partition
chip       : esp32
app: offset 0x0, entry 0x400811e8, 993,248 bytes selected
  app: eh_cp_bt_wifi_hosted_hci_mcu 1, IDF v5.5.5, built Jul 27 2026 16:29:02
  0x3f400020   241,380  data  drom  image+0x20
  0x3ffbdb60    20,748  data  dram  image+0x3af0c
  0x400d0020   637,532  code  irom  image+0x40020
  0x3ffc2c6c     2,996  data  dram  image+0xdba84
  0x40080000    90,440  code  iram  image+0xdc640
  0x50000000        32  data  rtc_data  image+0xf2790
```

### Create a Ghidra-loadable ELF

```sh
espfw elf flash.bin app0.elf --slot app0
```

The generated ELF maps every image segment at its real virtual address and
preserves code/data permissions. It intentionally contains no inferred symbols.
Import it into Ghidra as `Xtensa:LE:32:default`.

### Match symbols

```sh
espfw symbols app0.bin
espfw symbols app0.elf
espfw symbols flash.bin --slot app0
```

No version or `sdkconfig` is required. `symbols`:

1. Recovers function boundaries with the Espressif Xtensa `objdump`.
2. Canonicalizes each recovered function.
3. Searches every current corpus build for the detected chip.
4. Prints the ELF virtual address, source-image file offset, matching symbol
   name, and every corpus build that supplied that signature.

```text
$ espfw symbols network_adapter_esp32.bin

network_adapter_esp32.bin  chip esp32
corpus     : 22 build(s), 12 version(s)
matched    : 2,032 of 4,725 functions (43.0%)

ELF ADDRESS  IMAGE OFFSET  SIZE   SYMBOL  CORPUS SOURCE(S)
0x400efc2c  0x0005fc2c       24  hmac_sha1_vector  25:v5.4/default, 26:v5.4/size
0x400f4478  0x00064478       18  mbedtls_cipher_init  25:v5.4/default, 26:v5.4/size, 43:v6.0/default, 44:v6.0/size, 45:v6.1/default, 46:v6.1/size
0x4008474c  0x000e0d8c      165  coex_core_request  55:v5.5.3/size, 56:v5.5.5/size
0x400846cc  0x000e0d0c       84  coex_core_ts_end  56:v5.5.5/size
```

A source identifies the ESP-IDF or Arduino version, config name and hash, chip,
toolchain, canonicalizer version, build ID, and creation time. `corpus_source_ids`
identifies the builds that supplied the selected name. Alternative names sharing
the same canonical form remain visible in `ambiguous_with`.

All-corpus mode is exact-only. Modified-function detection did not run. An empty
result is not a clean-code verdict.

For an ELF input, `IMAGE OFFSET` is the offset in that ELF. For a `.bin` input,
it is the offset in the binary or flash dump. `ELF ADDRESS` is the virtual
address to use in Ghidra in either case.

After the hit statistics comes the **layout**: one bar per code segment showing
which addresses the corpus identified (`█`), which sit between identified
functions of one component (`▒`), and which nothing claims (`·`).

```text
layout: █ identified  ▒ inferred from neighbours  · unidentified
  iram  0x40080000  ·············████████████···▒▒·██·····████████████████████··▒▒▒·   90,440 bytes
  irom  0x400d0020  ··············▒▒▒▒▒███████████████████·▒▒▒▒▒▒▒▒▒▒▒▒·██████·█·▒█  637,532 bytes

regions no component claims (>= 2 KB), largest first:
  START       END         BYTES    FUNCS  BETWEEN
  0x400d8734  0x400e759e   61,034    517  vfs | esp_driver_gpio
  0x400f1ccc  0x400f585e   15,250    137  esp_driver_sdio | mbedcrypto
  0x400eae28  0x400edf26   12,542     96  esp_hw_support | nvs_flash
```

The linker lays code out in link order, so a component's functions are
neighbours, and an unmatched function between two `lwip` matches is almost
certainly `lwip` code that differs from the cached build rather than application
code. That inference is reported as `likely_component` on every unidentified
function and as `layout[]` regions in the JSON. The regions nothing claims are
listed separately. That is where the application is.

## Corpus

Corpus data is persistent SQLite at `~/.cache/espfw/corpus.sqlite`, or at
`$ESPFW_CACHE_DIR/corpus.sqlite`. Override it per invocation with `--cache-dir`.
The published `mkrlabs/espfw` image (above) is the quickest way to obtain a
populated corpus without building one.

```sh
espfw corpus list

# Docker-backed ESP-IDF build, explicit and never triggered by analysis.
espfw corpus build --version v5.4 --chip esp32 --config default

# Import an existing build tree without Docker.
espfw corpus build --version v5.4 --chip esp32 \
  --from-artifacts /path/to/build-output

espfw corpus build-arduino --core 2.0.14
espfw corpus rm --version v5.4 --config-hash ab12cd34 --yes
espfw corpus gc --dry-run
espfw corpus gc
```

Existing corpus databases are used directly. No rebuild or migration is needed,
and databases written by earlier versions of the tool remain readable.

## JSON

Pass `--json` for a JSON envelope or `-o FILE` for indented JSON in a file.
These options work before or after the selected command.

```sh
espfw symbols app0.bin -o symbols.json
jq '.result.identified[] | {vaddr_hex, name, corpus_source_ids}' symbols.json
```

Every output has this shape:

```json
{
  "command": "symbols",
  "provenance": {},
  "warnings": [],
  "result": {}
}
```

Important symbol fields:

- `corpus_sources`: every current build searched for the detected chip
- `identified[].vaddr` and `vaddr_hex`: address in the mapped ELF/Ghidra
- `identified[].offset`: corresponding offset in the input file
- `identified[].name`: deterministic preferred name
- `identified[].ambiguous_with`: other names sharing the canonical form
- `identified[].corpus_source_ids`: matching build IDs, resolved through
  `corpus_sources`
- `coverage`: recovered functions matched versus total recovered functions

## Environment

- `ESPFW_CACHE_DIR`: corpus and boundary cache root
- `ESPFW_TOOLCHAIN_DIR`: directory containing Espressif binutils
- `ESPFW_OBJDUMP_ESP32`, `ESPFW_OBJDUMP_ESP32S2`,
  `ESPFW_OBJDUMP_ESP32S3`: explicit `objdump` paths

## Development

```sh
uv run pytest
python -S -m espfw --help
```

The second command verifies that the CLI imports without site packages.

Much of `espfw` is written with Claude Code, Anthropic's agentic CLI. Design,
the test suite, and review are human-directed, and each release is verified
against real firmware before it ships.

## License

`espfw` is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE) for
the full terms and [`NOTICE`](NOTICE) for attribution. Reuse, including in
commercial and closed-source products, is permitted provided the license and
notices are retained.

```text
SPDX-License-Identifier: Apache-2.0
Copyright 2026 MKR Labs AS
```
