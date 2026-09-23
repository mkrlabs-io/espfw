#!/usr/bin/env bash
# Compile the probe sketch inside an espfw-arduino image and export what the
# harvester needs (§9.1). Mirrors docker_build.sh for the ESP-IDF path.
#
# Arguments: <fqbn>   e.g. esp32:esp32:esp32
set -uo pipefail

FQBN="${1:-esp32:esp32:esp32}"
# The chip is the FQBN's *third* field (vendor:arch:board[:options]), not the
# last: with build options appended the last field is "DebugLevel=verbose", which
# silently pointed the archive and sdkconfig lookups at a directory that does not
# exist and cost 20,000 of 26,000 signatures.
#
# Getting the chip wrong is a correctness problem, not just a coverage one: the
# core ships archives for esp32, esp32s2, esp32s3 *and* the RISC-V esp32c3, all
# with identical basenames.
CHIP=$(printf '%s' "$FQBN" | cut -d: -f3)
WORK=/tmp/espfw-arduino
SKETCH="$WORK/probe"

rm -rf "$WORK"
mkdir -p "$SKETCH"
cp /probe/probe.ino "$SKETCH/"

mkdir -p /out/archives /out/app

# --build-path keeps the intermediate objects and archives, which is where the
# coverage is: the linked sketch is a slice, the archives are the whole core.
if ! arduino-cli compile \
      --fqbn "$FQBN" \
      --build-path "$WORK/build" \
      --warnings none \
      --export-binaries \
      "$SKETCH"; then
    echo "espfw: arduino-cli compile failed" >&2
    exit 1
fi

# The core ships precompiled ESP-IDF archives; the build produces its own for the
# core and each library. Both are wanted.
find "$WORK/build" -name '*.a' -print0 2>/dev/null | while IFS= read -r -d '' a; do
    cp -n "$a" /out/archives/ 2>/dev/null || true
done
# The core's precompiled ESP-IDF archives, for *this chip only*. Searching the
# whole core tree copies esp32c3/esp32s2/esp32s3 archives too, and because they
# share basenames with the esp32 ones, `cp -n` lets whichever is found first win
# -- which silently substituted RISC-V archives and left libfreertos, liblwip and
# libesp_system out of the corpus entirely.
CORE_DIR=$(dirname "$(find /opt/arduino/packages/esp32/hardware -name 'platform.txt' | head -1)")
SDK_LIB="$CORE_DIR/tools/sdk/$CHIP/lib"
# 1.0.x cores support the ESP32 only and keep the archives one level up, with
# no chip directory. Without this fallback a 1.0.6 build harvested 612
# functions instead of the ~5,000 the 89 precompiled archives hold.
if [ ! -d "$SDK_LIB" ] && [ "$CHIP" = "esp32" ] && [ -d "$CORE_DIR/tools/sdk/lib" ]; then
    SDK_LIB="$CORE_DIR/tools/sdk/lib"
fi
if [ -d "$SDK_LIB" ]; then
    find "$SDK_LIB" -maxdepth 1 -name '*.a' -print0 2>/dev/null | while IFS= read -r -d '' a; do
        cp -n "$a" /out/archives/ 2>/dev/null || true
    done
    echo "espfw: copied $(find "$SDK_LIB" -maxdepth 1 -name '*.a' | wc -l) precompiled archives for $CHIP" >&2
else
    echo "espfw: no precompiled archive dir at $SDK_LIB" >&2
fi
# Flash-mode variants (dio_qspi/dout_qspi/qio_qspi) hold another copy of a few
# libraries built for a different flash mode. They are deliberately skipped: they
# collide by basename with the ones above and flash mode is not an axis this
# corpus models.

cp "$WORK"/build/*.elf /out/app/ 2>/dev/null || true
cp "$WORK"/build/*.bin /out/app/ 2>/dev/null || true

# Identity of what was actually built, so the corpus keys on facts rather than on
# the version string someone asked for.
cp /opt/arduino-core.txt /out/ 2>/dev/null || true
cp /opt/arduino-libs.txt /out/ 2>/dev/null || true
cp /opt/arduino-cli.txt /out/ 2>/dev/null || true

# The bundled ESP-IDF version. An Arduino image's esp_app_desc reports *this*,
# not the core version.
IDF_HDR=$(find "$CORE_DIR/tools/sdk/$CHIP" -name 'esp_idf_version.h' 2>/dev/null | head -1)
[ -z "$IDF_HDR" ] && IDF_HDR=$(find "$CORE_DIR" -name 'esp_idf_version.h' 2>/dev/null | head -1)
if [ -n "$IDF_HDR" ]; then
    awk '/ESP_IDF_VERSION_(MAJOR|MINOR|PATCH)/ {print $2"="$3}' "$IDF_HDR" > /out/bundled_idf.txt
fi
# The core's own sdkconfig stands in for the one an IDF build would produce, and
# it is what the config hash is computed from -- so it has to be this chip's.
SDKCONFIG=$(find "$CORE_DIR/tools/sdk/$CHIP" -maxdepth 2 -name 'sdkconfig' 2>/dev/null | head -1)
if [ -n "$SDKCONFIG" ]; then
    cp "$SDKCONFIG" /out/sdkconfig.out
    grep -h '^CONFIG_IDF_TARGET' "$SDKCONFIG" >> /out/bundled_idf.txt 2>/dev/null || true
fi

# objdump lives in the core's toolchain package, not on PATH. Recording the
# wrong thing here would put "arduino-unknown" in the toolchain axis, which is
# load-bearing: same source, different compiler, wholesale codegen differences.
OBJDUMP=$(find /opt/arduino/packages/esp32/tools -name "xtensa-${CHIP}-elf-objdump" 2>/dev/null | head -1)
[ -z "$OBJDUMP" ] && OBJDUMP=$(find /opt/arduino/packages/esp32/tools -name 'xtensa-*-elf-objdump' 2>/dev/null | head -1)
if [ -n "$OBJDUMP" ]; then
    "$OBJDUMP" --version 2>/dev/null | head -1 > /out/objdump_version.txt || true
fi

chmod -R a+rwX /out
echo "espfw: arduino build complete for $FQBN"
