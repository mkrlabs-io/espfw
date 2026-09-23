# Reading Results

All JSON output is an envelope with `command`, `provenance`, `warnings`, and
`result`. Read warnings before using the result.

## `flash-info`

Use `selected_image` to index `images`. Every segment has a mandatory
`file_offset`, `load_addr`, `length`, `region`, and `executable` field. A false
checksum/hash or differing OTA slots is significant.

## `elf`

`sections` is the address map. `vaddr` is the address in Ghidra;
`file_offset` refers to the source firmware image, not the newly written ELF.
The generated ELF deliberately has no inferred symbol table.

## `symbols`

- `corpus_sources`: all current builds searched
- `coverage.matched`: target functions with at least one exact corpus hit
- `coverage.total`: all recovered target functions
- `identified[].vaddr_hex`: address to use in Ghidra
- `identified[].offset`: offset in the input `.bin`, flash dump, or ELF
- `identified[].name`: preferred deterministic name
- `identified[].ambiguous_with`: alternative names with identical code
- `identified[].corpus_source_ids`: build IDs supplying the selected name/form

Resolve `corpus_source_ids` against top-level `corpus_sources`. Alternative names
sharing the same form are reported separately in `ambiguous_with`.

All-corpus matching is exact-only. `near_miss.available` is false by design, so
the result does not claim that the firmware contains no modified SDK functions.
