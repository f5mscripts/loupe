#!/usr/bin/env bash
#
# Builds the Loupe device-services FFI (idevice) into LoupeFFI.xcframework.
#
#   rust/  --(cargo, per-slice staticlib)-->  libloupe_ffi.a
#          --(cbindgen)-->                     LoupeFFI.h
#          --(assemble + modulemap)-->         build/xcframework/LoupeFFI.xcframework
#
# Prereqs:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   cargo install cbindgen
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$ROOT/rust"
OUT="$ROOT/build"
XC="$OUT/xcframework"
HDR_DIR="$OUT/include"
LIB_NAME="libloupe_ffi.a"

echo "==> Building Rust FFI slices"
cd "$RUST_DIR"

# Device (arm64) and simulator slices. Add x86_64-apple-ios for Intel sim if needed.
TARGETS_DEVICE=("aarch64-apple-ios")
TARGETS_SIM=("aarch64-apple-ios-sim")

for t in "${TARGETS_DEVICE[@]}" "${TARGETS_SIM[@]}"; do
  echo "    cargo build --release --target $t"
  cargo build --release --target "$t"
done

echo "==> Generating C header with cbindgen"
mkdir -p "$HDR_DIR"
cbindgen --config "$RUST_DIR/cbindgen.toml" --crate loupe_ffi --output "$HDR_DIR/LoupeFFI.h"

# A modulemap so Swift can `import LoupeFFI`.
cat > "$HDR_DIR/module.modulemap" <<'EOF'
module LoupeFFI {
    header "LoupeFFI.h"
    export *
}
EOF

echo "==> Assembling simulator fat lib (if multiple sim arches)"
SIM_LIBS=()
for t in "${TARGETS_SIM[@]}"; do SIM_LIBS+=("$RUST_DIR/target/$t/release/$LIB_NAME"); done
SIM_OUT="$OUT/sim/$LIB_NAME"
mkdir -p "$OUT/sim"
if [ "${#SIM_LIBS[@]}" -gt 1 ]; then
  lipo -create "${SIM_LIBS[@]}" -output "$SIM_OUT"
else
  cp "${SIM_LIBS[0]}" "$SIM_OUT"
fi

DEV_LIB="$RUST_DIR/target/${TARGETS_DEVICE[0]}/release/$LIB_NAME"

echo "==> Building LoupeFFI.xcframework"
rm -rf "$XC/LoupeFFI.xcframework"
mkdir -p "$XC"
xcodebuild -create-xcframework \
  -library "$DEV_LIB" -headers "$HDR_DIR" \
  -library "$SIM_OUT" -headers "$HDR_DIR" \
  -output "$XC/LoupeFFI.xcframework"

echo "==> Done: $XC/LoupeFFI.xcframework"
