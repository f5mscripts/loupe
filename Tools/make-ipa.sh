#!/usr/bin/env bash
#
# Build Loupe into an installable .ipa. macOS + Xcode 27 only.
#
# Pipeline:   build-rust.sh  →  xcodegen generate  →  xcodebuild archive  →  .ipa
#
# Two modes:
#   signed    (default) — exports a code-signed .ipa using Tools/ExportOptions.plist
#                         and your paid-account signing. Ready to install.
#   unsigned             — archives without signing and zips Payload/ into an .ipa
#                         for a re-signing sideloader (AltStore, Sideloadly, ...).
#
# Usage:
#   Tools/make-ipa.sh                 # signed (needs TEAM_ID set below / in files)
#   Tools/make-ipa.sh unsigned        # unsigned Payload .ipa for a sideloader
#
set -euo pipefail

MODE="${1:-signed}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SCHEME="Loupe"
PROJECT="Loupe.xcodeproj"
BUILD="$ROOT/build"
ARCHIVE="$BUILD/Loupe.xcarchive"
IPA_DIR="$BUILD/ipa"

command -v xcodebuild >/dev/null || { echo "!! xcodebuild not found — run this on macOS with Xcode 27."; exit 1; }
command -v xcodegen  >/dev/null || { echo "!! xcodegen not found — brew install xcodegen"; exit 1; }

echo "==> 1/4  Building Rust FFI (idevice → LoupeFFI.xcframework)"
./build-rust.sh

echo "==> 2/4  Generating Xcode project"
xcodegen generate

echo "==> 3/4  Archiving ($MODE)"
rm -rf "$ARCHIVE" "$IPA_DIR"
mkdir -p "$IPA_DIR"

if [ "$MODE" = "unsigned" ]; then
  xcodebuild archive \
    -project "$PROJECT" -scheme "$SCHEME" \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
    | xcpretty 2>/dev/null || true

  echo "==> 4/4  Packaging unsigned Payload .ipa"
  APP="$(find "$ARCHIVE/Products/Applications" -maxdepth 1 -name '*.app' | head -n1)"
  [ -d "$APP" ] || { echo "!! No .app in archive"; exit 1; }
  rm -rf "$BUILD/Payload"
  mkdir -p "$BUILD/Payload"
  cp -R "$APP" "$BUILD/Payload/"
  ( cd "$BUILD" && zip -qr "$IPA_DIR/Loupe-unsigned.ipa" Payload && rm -rf Payload )
  echo "==> Done: $IPA_DIR/Loupe-unsigned.ipa"
  echo "    Sign + install it with AltStore / Sideloadly (they use YOUR Apple ID)."
else
  xcodebuild archive \
    -project "$PROJECT" -scheme "$SCHEME" \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE" \
    | xcpretty 2>/dev/null || true

  echo "==> 4/4  Exporting signed .ipa"
  xcodebuild -exportArchive \
    -archivePath "$ARCHIVE" \
    -exportPath "$IPA_DIR" \
    -exportOptionsPlist "$ROOT/Tools/ExportOptions.plist" \
    | xcpretty 2>/dev/null || true
  echo "==> Done. Signed .ipa in: $IPA_DIR"
  echo "    (If export failed on signing, set teamID in Tools/ExportOptions.plist"
  echo "     and DEVELOPMENT_TEAM in project.yml, or use: Tools/make-ipa.sh unsigned)"
fi
