#!/usr/bin/env bash
# Build one ESP-IDF application inside the official IDF Docker image and export
# everything the harvester needs.
#
# Run with the ESP-IDF image's default entrypoint, which sources export.sh.
# Arguments: <target-chip>
set -euo pipefail

CHIP="${1:?usage: docker_build.sh <chip>}"

# ESPFW_APP_REL names an example relative to IDF_PATH, whose value only exists
# inside the container -- a caller on the host cannot expand it. ESPFW_APP_SRC
# remains available for an absolute path that the caller has mounted itself.
if [ -n "${ESPFW_APP_REL:-}" ]; then
    APP_SRC="$IDF_PATH/$ESPFW_APP_REL"
else
    APP_SRC="${ESPFW_APP_SRC:-$IDF_PATH/examples/get-started/hello_world}"
fi
if [ ! -d "$APP_SRC" ]; then
    echo "espfw: no such application in this IDF version: $APP_SRC" >&2
    exit 3
fi
WORK=/tmp/espfw-build

rm -rf "$WORK"
cp -r "$APP_SRC" "$WORK"
cd "$WORK"

# A caller-supplied sdkconfig becomes the defaults, so the build is reproducible
# from the config alone rather than from whatever was left in the tree.
if [ -f /out/sdkconfig.defaults ]; then
    cp /out/sdkconfig.defaults "$WORK/sdkconfig.defaults"
fi
rm -f sdkconfig

# `set-target` arrived with the multi-target support in IDF v4.0. On v3.3.x --
# the oldest official image, and ESP32-only anyway -- the subcommand does not
# exist, so its absence is not an error.
if ! idf.py set-target "$CHIP" >/dev/null 2>&1; then
    if [ "$CHIP" != "esp32" ]; then
        echo "espfw: this IDF version cannot target $CHIP (no set-target support)" >&2
        exit 2
    fi
    echo "espfw: no set-target in this IDF version; building for esp32" >&2
fi

if [ -n "${ESPFW_JOBS:-}" ] && [ "${ESPFW_JOBS}" != "0" ]; then
    idf.py build -j "$ESPFW_JOBS"
else
    idf.py build
fi

mkdir -p /out/archives /out/app

# Intermediate archives carry full symbol tables and every function, an order of
# magnitude more coverage than the linked application, which --gc-sections has
# already thinned.
find build -name '*.a' -print0 | while IFS= read -r -d '' a; do
    cp -n "$a" /out/archives/ 2>/dev/null || true
done

# The precompiled blobs ship as binaries and are bit-identical across everyone's
# builds regardless of sdkconfig, so they are worth fingerprinting directly --
# including the ones hello_world never links. Paths moved between releases:
# the BT controller is components/bt/lib in 3.x and bt/controller/lib_<chip> in
# 4.x+, coexistence moved from esp_wifi/lib to esp_coex/lib in 5.x.
for blob in "$IDF_PATH"/components/esp_wifi/lib/"$CHIP"/*.a \
            "$IDF_PATH"/components/esp_phy/lib/"$CHIP"/*.a \
            "$IDF_PATH"/components/esp_coex/lib/"$CHIP"/*.a \
            "$IDF_PATH"/components/bt/controller/lib_"$CHIP"/"$CHIP"/*.a \
            "$IDF_PATH"/components/bt/controller/lib_"$CHIP"/*.a \
            "$IDF_PATH"/components/bt/lib/*.a; do
    [ -f "$blob" ] && cp -n "$blob" /out/archives/ || true
done

# The toolchain's own runtime libraries. These are not IDF components and do
# not appear under build/, but their code is linked into every image and it
# changes when Espressif bumps the compiler -- which happens between IDF
# releases and is a different thing from an IDF change. Harvesting them under a
# distinguishable name keeps that difference visible. `-print-file-name`
# echoes its argument back
# when the library is absent, hence the -f test.
for lib in libc.a libm.a libgcc.a libstdc++.a libnosys.a; do
    path=$(xtensa-"$CHIP"-elf-gcc -print-file-name="$lib" 2>/dev/null || true)
    [ -n "$path" ] && [ -f "$path" ] && cp -n "$path" "/out/archives/libtoolchain-${lib}"
done

# The linked ELF is the fidelity reference: it is the only artifact that has
# been through linker relaxation, exactly like the code in a real image.
cp build/*.elf /out/app/ 2>/dev/null || true
cp build/*.bin /out/app/ 2>/dev/null || true
cp build/bootloader/bootloader.elf /out/app/ 2>/dev/null || true
cp sdkconfig /out/sdkconfig.out
idf.py --version > /out/idf_version.txt 2>/dev/null || true
xtensa-"$CHIP"-elf-objdump --version | head -1 > /out/objdump_version.txt 2>/dev/null || true

# Files are created as root inside the container; make them readable outside.
chmod -R a+rwX /out
echo "espfw: build complete for $CHIP"
