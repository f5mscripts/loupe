#!/usr/bin/env bash
#
# Builds the Loupe device-services FFI (idevice) into LoupeFFI.xcframework.
# Device-only (aarch64-apple-ios) — CI archives for a real device; add the sim
# slice back if you need to run in the Simulator.
#
# Prereqs: rustup target add aarch64-apple-ios ; cargo install cbindgen
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$ROOT/rust"
OUT="$ROOT/build"
XC="$OUT/xcframework"
HDR_DIR="$OUT/include"
LIB_NAME="libloupe_ffi.a"
DEVICE_TARGET="aarch64-apple-ios"

echo "==> Building Rust FFI ($DEVICE_TARGET)"
cd "$RUST_DIR"
cargo build --release --target "$DEVICE_TARGET"

echo "==> Generating C header with cbindgen"
mkdir -p "$HDR_DIR"
cbindgen --config "$RUST_DIR/cbindgen.toml" --crate loupe_ffi --output "$HDR_DIR/LoupeFFI.h"
cat > "$HDR_DIR/module.modulemap" <<'EOF'
module LoupeFFI {
    header "LoupeFFI.h"
    export *
}
EOF

DEV_LIB="$RUST_DIR/target/$DEVICE_TARGET/release/$LIB_NAME"

echo "==> Building LoupeFFI.xcframework (device slice)"
rm -rf "$XC/LoupeFFI.xcframework"
mkdir -p "$XC"
xcodebuild -create-xcframework \
  -library "$DEV_LIB" -headers "$HDR_DIR" \
  -output "$XC/LoupeFFI.xcframework"

echo "==> Done: $XC/LoupeFFI.xcframework"
