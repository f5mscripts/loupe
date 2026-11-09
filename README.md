# Loupe

**A per-app traffic instrument for iOS 27+.** On-device pairing → JIT → passive
capture (pcapd) → in-app Frida hooks that let you **see, edit, and resend** a
target app's API traffic. Think "Burp focused through runtime instrumentation"
instead of a network proxy.

> **For inspecting your own apps and devices, or systems you are explicitly
> authorized to test. Nothing here is designed to touch other people's devices.**
> See [Ethics & Scope](#ethics--scope). First launch shows a consent screen you
> must accept.

---

## Why this architecture (read this before touching the code)

Loupe is built on the iOS 27 **on-device pairing** mechanism (StikPair-style
wireless pairing). A pairing file + the lockdown developer services give you four
primitives, each with a hard boundary that the code respects:

| Primitive | Service | What it gives you | Hard limit |
|---|---|---|---|
| **JIT enablement** | `debugserver` | Attach to a target, flip the JIT/`CS_DEBUGGED` bit, detach. Required for Frida's Interceptor to compile hooks on non-jailbroken iOS. | Only for apps you can debug (your signing identity / re-signed apps). |
| **Passive capture** | `pcapd` | A live packet feed off the device's interfaces → flow metadata (SNI/host, ports, bytes, timing). | **READ-ONLY. HTTPS is ciphertext.** It is a *sniffer*, never a way to edit a response. |
| **App listing / files** | `installation_proxy`, `AFC` | Enumerate installed apps, read container files, push/pull. | Standard lockdown scope. |
| **Install** | `installation_proxy` | Sideload a re-signed IPA. | Needs your dev cert + provisioning. |

### The two layers, and why editing lives in the second one

```
                    ┌─────────────────────────────────────────┐
  pcapd (read-only) │  ciphertext   ← you SEE that a flow      │
  ───────────────►  │  flow metadata   happened, host, bytes   │
                    └─────────────────────────────────────────┘
                                    ▲ cannot decrypt, cannot edit
                                    │
   Frida hooks       ┌─────────────────────────────────────────┐
   INSIDE the app    │  plaintext    ← you SEE + EDIT + RESEND  │
   ───────────────►  │  full req/resp   because the hook sits   │
   (above TLS)       │  pairs           ABOVE TLS in-process    │
                    └─────────────────────────────────────────┘
```

- **pcapd is the "see everything" layer.** Every flow on the device, but HTTPS
  bodies are encrypted. Loupe labels these flows `encrypted` and marks the whole
  layer **read-only** in the UI. You cannot edit a pcapd flow. Full stop.
- **Frida is the "see + edit" layer.** The hook runs *inside the target process*,
  intercepting `NSURLSession` / `CFNetwork` / boringssl read-write paths **above
  the TLS boundary**, so it sees plaintext and can mutate it. This is also why
  **TLS pinning is irrelevant** here — the hook reads the data after the app has
  already decrypted it (response) or before it is encrypted (request).

**JIT is the bridge.** Frida's `Interceptor`/`Stalker` generate code at runtime.
On stock iOS that is blocked unless the process is `CS_DEBUGGED`. The pairing
file lets us set that bit via `debugserver` without a jailbreak.

### The instrumentable-targets reality (do not pretend otherwise)

On a **non-jailbroken** device, Frida **cannot** freely attach to an arbitrary
running App Store app — that requires `frida-server`, which requires a jailbreak.
Loupe is built around the only two targets that *are* instrumentable on stock iOS:

1. **(a) Your OWN apps** — anything built/signed with your developer identity.
   JIT + a gadget you link, or JIT + debugserver attach.
2. **(b) Third-party apps you RE-SIGN yourself** — take a *decrypted* IPA, embed
   `FridaGadget.dylib`, re-sign with *your* dev cert, sideload. The gadget loads
   at launch and opens the hook channel.

Loupe will **never** claim it can hook an app it has not instrumented. The Apps
tab tags every app as `instrumented` (gadget present / own app) or
`capture-only` (pcapd metadata only). Capture-only apps can be *seen* but not
*edited* — the UI enforces this.

### pcapd-is-read-only caveat (say it twice because it matters)

If you only pair + run pcapd, you get a flow list of hosts and sizes, and for
HTTPS that's all you'll ever get. **Editing/resending requires the target to be
instrumented (own app or re-signed with the gadget).** No exceptions, no "and
then it decrypts TLS for you" — that is not how read-only packet capture works.

---

## Milestones

The project is organized and committed so each milestone is independently
demoable. Each builds on the last.

- **M1 — Pairing + tunnel + status UI.** Import/generate a pairing file, stand up
  the on-device lockdown tunnel to `localhost`, mount the DeveloperDiskImage,
  verify Developer Mode. Setup tab shows each prerequisite: *Paired · DDI · Tunnel*.
- **M2 — JIT enable.** Pick a target bundle id, enable JIT via debugserver
  (attach → set `CS_DEBUGGED` → detach), StikDebug-style. Per-app JIT status.
- **M3 — pcapd capture + flow list.** Start/stop a passive sniff, parse packets
  into flows (host/SNI, ports, timing, bytes), mark `encrypted` vs `plaintext`.
  Read-only layer.
- **M4 — Frida hook → full decrypted flows.** For an instrumented target, load
  the hook script; it intercepts the app's networking and streams full decrypted
  request/response pairs over a local channel. See + edit layer; pinning defeated.
- **M5 — Edit/resend.** Breakpoints (pause req/resp, edit, forward/drop),
  Match & Replace rules, Map Local, Repeater, HAR/cURL/.pcap export.

---

## Project layout

```
Loupe/
├── project.yml                 # xcodegen project definition
├── build-rust.sh               # idevice (Rust) → LoupeFFI.xcframework
├── rust/                       # idevice FFI crate (lockdown, debugserver, pcapd, AFC, install)
│   ├── Cargo.toml
│   ├── cbindgen.toml
│   └── src/lib.rs
├── Sources/
│   ├── App/                    # SwiftUI: tabs, status bar, consent
│   ├── DeviceServices/         # Swift wrappers over the Rust FFI (pairing, tunnel, JIT, install)
│   ├── Capture/                # pcapd parse → flows
│   ├── Instrument/             # Frida manager + gadget config + hook .js
│   └── Shared/                 # Flow / Rule / AppProfile models, store, rule engine
├── Resources/
│   ├── FridaGadget/            # drop FridaGadget.dylib + config here (see its README)
│   └── Assets.xcassets/
└── Tools/
    └── resign-with-gadget.sh   # case (b): decrypt check → inject gadget → re-sign → sideload
```

---

## Build & run

### Prerequisites
- macOS with **Xcode 27**, a **paid Apple Developer** account configured in Xcode.
- [`xcodegen`](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).
- Rust toolchain with iOS targets:
  ```bash
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim
  ```
- `cbindgen` (`cargo install cbindgen`).

### Steps
```bash
# 1. Build the device-services FFI (idevice) into an xcframework.
./build-rust.sh

# 2. Generate the Xcode project.
xcodegen generate

# 3. Open and run on a *real device* (pairing/JIT/pcapd do nothing in the sim).
open Loupe.xcodeproj
```

Set your `DEVELOPMENT_TEAM` and a unique `PRODUCT_BUNDLE_IDENTIFIER` in
`project.yml` (or via `xcconfig`) before generating.

### Pairing
On first run the **Setup** tab asks for a pairing file. Two options:
1. **Import** a pairing file generated on-device (StikPair-style). Recommended.
2. **Generate in-app** (experimental) via the lockdown pairing flow.

The pairing file is stored in the app group and reused. Loupe detects an expired
or invalid pairing and prompts you to re-pair.

---

## Building an `.ipa`

An `.ipa` must be compiled and signed on **macOS with Xcode 27** — it cannot be
produced on Linux/CI without the Apple toolchain. One command does the whole
pipeline (Rust FFI → project → archive → ipa):

```bash
# Signed, install-ready .ipa (set your Team ID first — see below):
Tools/make-ipa.sh

# Unsigned Payload .ipa for a re-signing sideloader (AltStore / Sideloadly):
Tools/make-ipa.sh unsigned
```

Output lands in `build/ipa/`. Before a **signed** build, set your 10-char Team ID
in two places: `DEVELOPMENT_TEAM` in `project.yml` and `teamID` in
`Tools/ExportOptions.plist`. If signing export fails, use the `unsigned` mode and
let AltStore/Sideloadly sign with your Apple ID.

> Reminder: Loupe links `LoupeFFI.xcframework` (built by `build-rust.sh`) and
> embeds `FridaGadget.dylib` — drop the gadget in `Resources/FridaGadget/` first
> (see that folder's README), or the app build will be missing the hook binary.

### CI builds (Codemagic)

`codemagic.yaml` builds the `.ipa` on Codemagic's macOS runners — no local Mac
needed. Two workflows:

- **`loupe-unsigned`** — no credentials. Produces `build/Loupe-unsigned.ipa` as a
  build artifact; sign + install it with AltStore / Sideloadly. Quickest path.
- **`loupe-signed`** — install-ready, code-signed `.ipa`. Requires, in Codemagic:
  1. An **App Store Connect API key** integration named `Loupe ASC Key`
     (Team settings → Integrations), and
  2. An environment group `loupe_signing` defining `CERTIFICATE_PRIVATE_KEY`.

Both compile the Rust FFI and run xcodegen automatically. If you don't commit
`FridaGadget.dylib`, set a `FRIDA_GADGET_URL` env var (a gzipped
`frida-gadget-*-ios-universal.dylib`) and the build fetches it. Pin `xcode: latest`
→ `27` once Codemagic offers it.

### CI builds (GitHub Actions)

`.github/workflows/build-ipa.yml` does the same on GitHub's macOS runners. Push the
repo (with the Loupe project at the repo root) and it builds automatically:

- **`unsigned`** job — always runs, no secrets. Download `Loupe-unsigned.ipa` from
  the run's Artifacts; sign + install with AltStore / Sideloadly.
- **`signed`** job — runs only when repo **variable** `ENABLE_SIGNED_BUILD=true`,
  using these repo **secrets**: `APPLE_TEAM_ID`, `BUILD_CERTIFICATE_P12_BASE64`,
  `BUILD_CERTIFICATE_PASSWORD`, `PROVISIONING_PROFILE_BASE64` (and optionally
  `FRIDA_GADGET_URL`). Produces a code-signed `.ipa` artifact.

Bump `runs-on: macos-14` to the image shipping Xcode 27 (and uncomment the
`xcode-select -s /Applications/Xcode_27.app` line) when it's available — the iOS 27
deploy target needs it.

## Instrumenting a third-party app — the re-sign + gadget workflow (case b)

You can only do this with an app binary you are **authorized** to modify and that
is **decrypted** (App Store binaries are FairPlay-encrypted; decryption on a
device you control is a separate step this repo does not perform for you).

```bash
# You provide: a DECRYPTED Target.ipa, FridaGadget.dylib in Resources/FridaGadget/,
# your signing identity, and a provisioning profile that matches the new bundle id.
./Tools/resign-with-gadget.sh \
  --ipa ~/Decrypted/Target.ipa \
  --gadget Resources/FridaGadget/FridaGadget.dylib \
  --config Resources/FridaGadget/FridaGadget.config.so.json \
  --identity "Apple Development: you@example.com (XXXXXXXXXX)" \
  --profile  ~/profiles/loupe-target.mobileprovision \
  --out ~/Resigned/Target-gadget.ipa
```

The script:
1. Unzips the IPA, finds the main binary in `Payload/*.app`.
2. Copies the gadget into `*.app/Frameworks/` and adds an `LC_LOAD_DYLIB` via
   `install_name_tool` (`@executable_path/Frameworks/FridaGadget.dylib`).
3. Drops the gadget config next to it (listen mode on a local port / script dir).
4. Re-signs every nested binary + framework + the app with your identity and
   embeds the provisioning profile + entitlements.
5. Re-zips to a sideloadable IPA.

Sideload the result (Loupe's **Apps → Install**, or your tool of choice). The app
now launches with the gadget; Loupe's **Instrument** layer connects to it.

For **your own apps (case a)**: just add `FridaGadget.dylib` as a "Copy Files →
Frameworks" build phase and link it, or rely on JIT + debugserver. No re-sign dance.

---

## Data model

```swift
Flow   { id, ts, bundleId, source(.pcap|.frida), host, method, url,
         reqHeaders, reqBody, status, respHeaders, respBody, encrypted, edited }
Rule   { id, enabled, scope(bundleId/host), side(.req|.resp), matchType,
         pattern, action(.headerSet|.bodyReplace|.mapLocal|.breakpoint),
         replacement, order }
AppProfile { bundleId, name, instrumented, colorTag }
```

- pcapd flows arrive with `source = .pcap`, `encrypted = true` for HTTPS, and no
  bodies. Frida flows arrive with `source = .frida` and full decrypted payloads.
- For a focused app, Loupe **merges** the two: pcapd supplies the "something
  happened" timeline, Frida supplies the editable payloads.

---

## Ethics & Scope

Loupe exists for **authorized** work only:
- Inspecting/instrumenting **your own** apps and device.
- Testing systems **you are explicitly authorized** to test (e.g. a pentest
  engagement with scope, a bug-bounty target that permits it, a CTF).

It is deliberately built so it **cannot** target other people's devices: every
capability requires *your* pairing file, *your* signing identity, and *your*
re-signed binary. There is no remote-attach, no mass-targeting, no stealth
feature. First launch requires accepting a one-time consent screen that restates
this. Don't use it to intercept traffic you aren't allowed to.

---

## Status / honesty notes

This repo is a complete, buildable **scaffold** with the real architecture wired
end-to-end against the data model and UI. The device-touching calls in
`Sources/DeviceServices` are thin wrappers over the `idevice` Rust crate; the
exact crate function names/signatures move between versions, so those wrappers
are marked `// FFI:` and must be reconciled against the `idevice` version you
pin in `rust/Cargo.toml`. The Frida hook (`Sources/Instrument/hooks/interceptor.js`)
is complete and does the real work. Nothing here fakes a capability it doesn't
have — where a step needs real hardware to validate, the code says so.

<!-- Co-Authored-By: Claude Opus 4.8 -->
