# Corpus

The canonical store is SQLite at `~/.cache/espfw/corpus.sqlite`, overridden by
`ESPFW_CACHE_DIR`, `XDG_CACHE_HOME`, or `--cache-dir`.

Every signature belongs to one build keyed by version/framework string, config
hash, chip, toolchain, and canonicalizer version. Existing databases remain
compatible.

`symbols` searches every current build for the detected chip. It excludes stale
canonicalizer versions and other chips.
Each hit reports its concrete source build; identical code under several names
remains ambiguous rather than being guessed.

## Populate

```sh
espfw corpus build --version v5.4 --chip esp32 --config default
espfw corpus build --version v5.4 --chip esp32 \
  --from-artifacts /path/to/build-output
espfw corpus build-arduino --core 2.0.14
```

The normal IDF and Arduino paths invoke Docker. `--from-artifacts` ingests an
existing build tree and only needs Espressif `objdump`.

## Maintain

```sh
espfw corpus list
espfw corpus rm --version v5.4 --config-hash ab12cd34 --yes
espfw corpus gc --dry-run
espfw corpus gc
```

No analysis command builds or downloads corpus data. If the corpus is empty,
relay the remedy to the user and ask before starting a build.
