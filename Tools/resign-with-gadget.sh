#!/usr/bin/env bash
#
# Re-sign a DECRYPTED third-party IPA with FridaGadget embedded (case (b) from the
# README). The result is a sideloadable IPA whose target app loads interceptor.js at
# launch and opens the Loupe hook channel.
#
# AUTHORIZED USE ONLY. Only run this against an app binary you are allowed to modify.
# This script does NOT decrypt FairPlay-protected App Store binaries — supply a
# decrypted IPA.
#
# Requires: unzip, zip, codesign, install_name_tool, plutil, optionally `insert_dylib`
# (https://github.com/tyilo/insert_dylib) for the load command; falls back to
# install_name_tool -add_rpath + LC_LOAD_DYLIB via `optool` if present.
#
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --ipa <decrypted.ipa> --gadget <FridaGadget.dylib> --config <config.json>
          --identity <signing identity> --profile <profile.mobileprovision>
          --out <resigned.ipa> [--script <interceptor.js>]
EOF
  exit 1
}

SCRIPT_JS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ipa) IPA="$2"; shift 2;;
    --gadget) GADGET="$2"; shift 2;;
    --config) CONFIG="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    --profile) PROFILE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --script) SCRIPT_JS="$2"; shift 2;;
    *) usage;;
  esac
done
: "${IPA:?}" "${GADGET:?}" "${CONFIG:?}" "${IDENTITY:?}" "${PROFILE:?}" "${OUT:?}"
[ -z "$SCRIPT_JS" ] && SCRIPT_JS="$(dirname "$0")/../Sources/Instrument/hooks/interceptor.js"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Unpacking IPA"
unzip -q "$IPA" -d "$WORK"
APP="$(find "$WORK/Payload" -maxdepth 1 -name '*.app' | head -n1)"
[ -d "$APP" ] || { echo "No .app in Payload"; exit 1; }
BIN_NAME="$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
BIN="$APP/$BIN_NAME"
echo "    app: $APP"
echo "    bin: $BIN_NAME"

echo "==> Checking the binary is decrypted"
if otool -l "$BIN" | grep -q "cryptid 1"; then
  echo "!! Binary still has cryptid 1 (encrypted). Supply a DECRYPTED IPA." >&2
  exit 2
fi

echo "==> Embedding gadget + config + script"
mkdir -p "$APP/Frameworks"
cp "$GADGET" "$APP/Frameworks/FridaGadget.dylib"
cp "$CONFIG" "$APP/Frameworks/FridaGadget.config.so.json"
cp "$SCRIPT_JS" "$APP/Frameworks/interceptor.js"

echo "==> Adding LC_LOAD_DYLIB to the main binary"
LOAD_PATH="@executable_path/Frameworks/FridaGadget.dylib"
if command -v insert_dylib >/dev/null 2>&1; then
  insert_dylib --strip-codesig --inplace "$LOAD_PATH" "$BIN"
elif command -v optool >/dev/null 2>&1; then
  optool install -c load -p "$LOAD_PATH" -t "$BIN"
else
  echo "!! Need insert_dylib or optool to add the load command. Install one and re-run." >&2
  exit 3
fi

echo "==> Extracting entitlements from provisioning profile"
security cms -D -i "$PROFILE" > "$WORK/profile.plist"
/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' "$WORK/profile.plist" > "$WORK/entitlements.plist"
cp "$PROFILE" "$APP/embedded.mobileprovision"

echo "==> Re-signing nested code (frameworks, dylibs) then the app"
find "$APP" \( -name '*.dylib' -o -name '*.framework' -o -name '*.appex' \) -print0 \
  | while IFS= read -r -d '' item; do
      codesign --force --sign "$IDENTITY" --timestamp=none "$item"
    done
codesign --force --sign "$IDENTITY" --entitlements "$WORK/entitlements.plist" --timestamp=none "$BIN"
codesign --force --sign "$IDENTITY" --entitlements "$WORK/entitlements.plist" --timestamp=none "$APP"

echo "==> Verifying signature"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> Repacking IPA → $OUT"
( cd "$WORK" && zip -qr "$OUT" Payload )
echo "==> Done. Sideload $OUT, launch it, then Connect hook in Loupe."
