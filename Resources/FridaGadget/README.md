# FridaGadget assets

Loupe does **not** vendor the Frida gadget binary (it's large, versioned, and you
should fetch the build that matches your tooling). Drop it here.

## What to put in this folder

1. **`FridaGadget.dylib`** — the iOS/arm64 gadget from the Frida releases
   (`frida-gadget-<version>-ios-universal.dylib`, or the arm64 slice).
   Get it from https://github.com/frida/frida/releases (file
   `frida-gadget-*-ios-universal.dylib.gz`), gunzip, and rename to
   `FridaGadget.dylib`.

2. **`FridaGadget.config.so.json`** — already generated here by
   `GadgetConfig.configJSON()`. It tells the gadget to load `interceptor.js`
   at launch (interaction type `script`). If you regenerate it, keep the
   `interaction.type = "script"` and the path pointing at the bundled script.

3. **`interceptor.js`** — copied automatically by `Tools/resign-with-gadget.sh`
   from `Sources/Instrument/hooks/interceptor.js`. For your **own** apps (case a),
   add it + the gadget as a "Copy Files → Frameworks" build phase.

## Case (a) — your own app
Link `FridaGadget.dylib` (Frameworks phase, embed & sign), copy
`FridaGadget.config.so.json` and `interceptor.js` into `Frameworks/`. On launch the
gadget loads the script, which opens the loopback listener Loupe connects to.

## Case (b) — a third-party app you're authorized to modify
Use `Tools/resign-with-gadget.sh` with a **decrypted** IPA. It embeds all three
files, adds the load command, re-signs with your identity, and repacks.

> The gadget + JIT only make a target instrumentable if it's your own signing
> identity or a re-signed binary. You cannot attach to an untouched App Store app
> on stock iOS — that needs frida-server + a jailbreak. Loupe is built for the
> former, on purpose.
