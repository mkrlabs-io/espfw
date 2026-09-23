# syntax=docker/dockerfile:1
#
# espfw runtime image: espfw, the Espressif Xtensa objdump toolchain, and the
# prebuilt signature corpus, so `symbols` runs with no host setup.
#
# The corpus (~1 GB) lives outside the repo, so it is supplied as a named build
# context rather than copied in. Build from the repo root with BuildKit:
#
#   docker build \
#     --build-context corpus="$HOME/.cache/espfw" \
#     -t mkrlabs/espfw:latest .
#
# Then run against a firmware image in the current directory:
#
#   docker run --rm -v "$PWD:/work" -w /work mkrlabs/espfw symbols flash.bin
#
# and push:
#
#   docker push mkrlabs/espfw:latest
#
# Multi-arch (amd64 + arm64) in one shot:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-context corpus="$HOME/.cache/espfw" \
#     -t mkrlabs/espfw:latest --push .

# --- toolchain stage ------------------------------------------------------
# Fetch the exact objdump the corpus was disassembled with. A different build
# can change canonical forms and lower the match rate, so this is pinned to the
# same crosstool-NG release espfw resolved when the corpus was built
# (GNU objdump (crosstool-NG esp-13.2.0_20240530) 2.41).
FROM debian:bookworm-slim AS toolchain
ARG ESP_TOOLCHAIN=esp-13.2.0_20240530
ARG ESP_TC_VERSION=13.2.0_20240530
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64-linux-gnu ;; \
      arm64) arch=aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/espressif/crosstool-NG/releases/download/${ESP_TOOLCHAIN}/xtensa-esp-elf-${ESP_TC_VERSION}-${arch}.tar.xz"; \
    mkdir -p /opt; \
    curl -fSL "$url" | tar -xJ -C /opt; \
    /opt/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump --version | head -1

# --- runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="espfw" \
      org.opencontainers.image.description="ESP32 firmware inspector and corpus symbol matcher, with the prebuilt corpus and Xtensa toolchain" \
      org.opencontainers.image.source="https://github.com/mkrlabs-io/espfw" \
      org.opencontainers.image.documentation="https://mkrlabs.io/research/reading-esp32-firmware-with-espfw" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="MKR Labs AS"

# objdump needs a couple of shared libraries beyond the slim base.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libzstd1 zlib1g \
 && rm -rf /var/lib/apt/lists/*

# The Xtensa toolchain. espfw finds the objdump through ESPFW_TOOLCHAIN_DIR.
COPY --from=toolchain /opt/xtensa-esp-elf /opt/xtensa-esp-elf
ENV ESPFW_TOOLCHAIN_DIR=/opt/xtensa-esp-elf/bin \
    ESPFW_CACHE_DIR=/opt/espfw/cache \
    PATH=/opt/xtensa-esp-elf/bin:$PATH

# espfw itself. The package is standard-library only, so there is nothing to
# resolve from an index.
COPY pyproject.toml README.md LICENSE NOTICE /src/
COPY espfw /src/espfw
RUN pip install --no-cache-dir /src && rm -rf /src \
 && xtensa-esp32-elf-objdump --version | head -1 \
 && espfw --version

# The prebuilt corpus, from the named build context.
COPY --from=corpus corpus.sqlite /opt/espfw/cache/corpus.sqlite

WORKDIR /work
ENTRYPOINT ["espfw"]
CMD ["--help"]
