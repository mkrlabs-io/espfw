# A reproducible arduino-esp32 build environment, one image per core version.
#
# Built once per core version and then reused, because installing the core pulls
# a toolchain and the precompiled ESP-IDF libraries — several minutes and a few
# GB that should not be paid per corpus build.
#
# The core version is the whole point of the image, so it is the build arg.
FROM debian:bookworm-slim

ARG CORE_VERSION
ARG CLI_VERSION=1.1.1
ARG LIBRARIES=""

ENV DEBIAN_FRONTEND=noninteractive \
    ARDUINO_DIRECTORIES_DATA=/opt/arduino \
    ARDUINO_DIRECTORIES_DOWNLOADS=/opt/arduino/staging \
    ARDUINO_DIRECTORIES_USER=/opt/arduino/user

# python-is-python3: the 1.0.x cores' platform.txt invokes `python` for
# esptool and the partition generator, and Debian ships only `python3`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl python3 python3-pip python3-serial python-is-python3 \
      git xz-utils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh \
      | sh -s -- ${CLI_VERSION} \
 && mv bin/arduino-cli /usr/local/bin/ \
 && arduino-cli version

# The ESP32 board index is not in the default package list.
RUN arduino-cli config init \
      --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json \
 && arduino-cli core update-index \
 && arduino-cli core install esp32:esp32@${CORE_VERSION}

# Libraries are baked in so a corpus build is offline and repeatable. Failures
# are tolerated per library: the Library Manager's names drift, and one
# unavailable library must not cost the whole image.
RUN set -u; for lib in ${LIBRARIES}; do \
      name=$(printf '%s' "$lib" | tr '+' ' '); \
      arduino-cli lib install "$name" || echo "espfw: could not install '$name'" >&2; \
    done; arduino-cli lib list || true

# Record what this image actually is, so the corpus can key on facts rather than
# on the build argument it was asked for.
RUN arduino-cli core list > /opt/arduino-core.txt \
 && arduino-cli lib list > /opt/arduino-libs.txt \
 && arduino-cli version > /opt/arduino-cli.txt
