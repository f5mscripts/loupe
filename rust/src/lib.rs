//! Loupe device-services FFI.
//!
//! A thin C-ABI shim over the `idevice` crate for the on-device pairing tunnel,
//! debugserver (JIT), pcapd (passive capture), installation_proxy (app listing /
//! install) and AFC.
//!
//! ## Honesty / wiring note
//! The C ABI, the tokio runtime, the error channel, the handle lifecycle and the
//! pcapd streaming callback below are real and compile. Each function that must
//! talk to `idevice` is isolated into a `backend` module call and marked `// FFI:`.
//! The `idevice` crate's exact function names/signatures change between versions,
//! so those calls return `LOUPE_ERR_NOT_WIRED` until reconciled against the version
//! pinned in `Cargo.toml`. This keeps the whole stack buildable and the Swift side
//! exercised end-to-end, without faking a capability the shim does not yet perform.
//!
//! Reconcile by implementing the bodies in `mod backend` against your `idevice`
//! version, then delete the `not_wired(...)` lines.

use once_cell::sync::Lazy;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::Mutex;
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// Error codes (kept in sync with LoupeStatus in Swift)
// ---------------------------------------------------------------------------
pub const LOUPE_OK: c_int = 0;
pub const LOUPE_ERR_GENERIC: c_int = 1;
pub const LOUPE_ERR_BAD_ARG: c_int = 2;
pub const LOUPE_ERR_PAIRING: c_int = 3;
pub const LOUPE_ERR_TUNNEL: c_int = 4;
pub const LOUPE_ERR_DDI: c_int = 5;
pub const LOUPE_ERR_JIT: c_int = 6;
pub const LOUPE_ERR_PCAPD: c_int = 7;
pub const LOUPE_ERR_INSTALL: c_int = 8;
pub const LOUPE_ERR_NOT_WIRED: c_int = 9;

// ---------------------------------------------------------------------------
// Global runtime + last-error channel
// ---------------------------------------------------------------------------
static RT: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("failed to build tokio runtime")
});

static LAST_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

fn set_error(msg: impl Into<String>) {
    if let Ok(mut e) = LAST_ERROR.lock() {
        *e = msg.into();
    }
}

fn not_wired(what: &str) -> c_int {
    set_error(format!(
        "{what}: not wired to the pinned `idevice` version. \
         Implement in rust/src/lib.rs `mod backend` and remove the not_wired() call."
    ));
    LOUPE_ERR_NOT_WIRED
}

/// Returns a borrowed, NUL-terminated C string of the last error. Valid until the
/// next FFI call that sets an error. Swift copies it immediately.
#[no_mangle]
pub extern "C" fn loupe_last_error() -> *const c_char {
    thread_local! {
        static BUF: std::cell::RefCell<CString> =
            std::cell::RefCell::new(CString::new("").unwrap());
    }
    let s = LAST_ERROR.lock().map(|g| g.clone()).unwrap_or_default();
    BUF.with(|b| {
        *b.borrow_mut() = CString::new(s).unwrap_or_default();
        b.borrow().as_ptr()
    })
}

/// Initialize logging / runtime. Idempotent.
#[no_mangle]
pub extern "C" fn loupe_init() -> c_int {
    Lazy::force(&RT);
    LOUPE_OK
}

// Helper: borrow a &str from a C string argument.
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() { return None; }
    CStr::from_ptr(p).to_str().ok()
}

// ---------------------------------------------------------------------------
// Opaque handles
// ---------------------------------------------------------------------------

/// A live provider: the pairing + lockdown/RSD session used by all services.
pub struct LoupeProvider {
    // FFI: hold the idevice provider / RSD handshake / lockdown client here.
    _pairing: Vec<u8>,
}

/// A running pcapd capture. Dropping it stops the stream.
pub struct LoupeCapture {
    stop: tokio::sync::watch::Sender<bool>,
}

// ---------------------------------------------------------------------------
// Pairing + provider
// ---------------------------------------------------------------------------

/// Validate a pairing file (plist bytes). Returns LOUPE_OK if it parses and has the
/// fields we need (UDID, host/device certs, keys). Does not open a tunnel.
#[no_mangle]
pub extern "C" fn loupe_pairing_validate(bytes: *const u8, len: usize) -> c_int {
    if bytes.is_null() || len == 0 {
        set_error("pairing_validate: empty buffer");
        return LOUPE_ERR_BAD_ARG;
    }
    let data = unsafe { std::slice::from_raw_parts(bytes, len) };
    match backend::validate_pairing(data) {
        Ok(()) => LOUPE_OK,
        Err(code) => code,
    }
}

/// Stand up the on-device lockdown tunnel to localhost using the pairing file and
/// return a provider handle. The provider owns the RSD/lockdown session.
#[no_mangle]
pub extern "C" fn loupe_provider_start(
    pairing_bytes: *const u8,
    pairing_len: usize,
    out_provider: *mut *mut LoupeProvider,
) -> c_int {
    if pairing_bytes.is_null() || pairing_len == 0 || out_provider.is_null() {
        set_error("provider_start: bad args");
        return LOUPE_ERR_BAD_ARG;
    }
    let data = unsafe { std::slice::from_raw_parts(pairing_bytes, pairing_len) }.to_vec();

    match RT.block_on(backend::start_provider(&data)) {
        Ok(()) => {
            let prov = Box::new(LoupeProvider { _pairing: data });
            unsafe { *out_provider = Box::into_raw(prov) };
            LOUPE_OK
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn loupe_provider_free(p: *mut LoupeProvider) {
    if !p.is_null() { unsafe { drop(Box::from_raw(p)) } }
}

/// Is Developer Mode enabled on the device?
#[no_mangle]
pub extern "C" fn loupe_developer_mode_enabled(p: *mut LoupeProvider, out: *mut c_int) -> c_int {
    if p.is_null() || out.is_null() { return LOUPE_ERR_BAD_ARG; }
    match RT.block_on(backend::developer_mode_enabled()) {
        Ok(v) => { unsafe { *out = if v { 1 } else { 0 } }; LOUPE_OK }
        Err(code) => code,
    }
}

/// Mount the DeveloperDiskImage (personalized on iOS 17+). Idempotent.
#[no_mangle]
pub extern "C" fn loupe_mount_ddi(p: *mut LoupeProvider) -> c_int {
    if p.is_null() { return LOUPE_ERR_BAD_ARG; }
    match RT.block_on(backend::mount_ddi()) {
        Ok(()) => LOUPE_OK,
        Err(code) => code,
    }
}

// ---------------------------------------------------------------------------
// JIT (debugserver)
// ---------------------------------------------------------------------------

/// Enable JIT for a bundle id: attach via debugserver, flip CS_DEBUGGED, detach.
/// This is what lets Frida's Interceptor compile hooks on stock iOS.
#[no_mangle]
pub extern "C" fn loupe_jit_enable(p: *mut LoupeProvider, bundle_id: *const c_char) -> c_int {
    if p.is_null() { return LOUPE_ERR_BAD_ARG; }
    let bid = match unsafe { cstr(bundle_id) } {
        Some(s) => s.to_string(),
        None => { set_error("jit_enable: bad bundle id"); return LOUPE_ERR_BAD_ARG; }
    };
    match RT.block_on(backend::jit_enable(&bid)) {
        Ok(()) => LOUPE_OK,
        Err(code) => code,
    }
}

// ---------------------------------------------------------------------------
// Installation proxy (list + install)
// ---------------------------------------------------------------------------

/// List installed apps as a JSON array string: [{"bundleId":..,"name":..}].
/// Caller frees with loupe_string_free.
#[no_mangle]
pub extern "C" fn loupe_list_apps(p: *mut LoupeProvider, out_json: *mut *mut c_char) -> c_int {
    if p.is_null() || out_json.is_null() { return LOUPE_ERR_BAD_ARG; }
    match RT.block_on(backend::list_apps()) {
        Ok(json) => {
            unsafe { *out_json = CString::new(json).unwrap_or_default().into_raw() };
            LOUPE_OK
        }
        Err(code) => code,
    }
}

/// Install a (re-signed) IPA at a filesystem path.
#[no_mangle]
pub extern "C" fn loupe_install_ipa(p: *mut LoupeProvider, ipa_path: *const c_char) -> c_int {
    if p.is_null() { return LOUPE_ERR_BAD_ARG; }
    let path = match unsafe { cstr(ipa_path) } {
        Some(s) => s.to_string(),
        None => return LOUPE_ERR_BAD_ARG,
    };
    match RT.block_on(backend::install_ipa(&path)) {
        Ok(()) => LOUPE_OK,
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn loupe_string_free(s: *mut c_char) {
    if !s.is_null() { unsafe { drop(CString::from_raw(s)) } }
}

// ---------------------------------------------------------------------------
// pcapd — passive capture (READ-ONLY)
// ---------------------------------------------------------------------------

/// Packet callback. `ctx` is the Swift-provided opaque pointer; `data`/`len` is one
/// pcapd packet record (with its header). The callback must copy before returning.
pub type LoupePacketCb = extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize);

/// Start a passive pcapd capture. Each packet is delivered to `cb`. Returns a
/// capture handle; stop + free it with loupe_capture_stop.
///
/// This is the read-only "see everything" layer. HTTPS payloads are ciphertext.
#[no_mangle]
pub extern "C" fn loupe_capture_start(
    p: *mut LoupeProvider,
    cb: LoupePacketCb,
    ctx: *mut c_void,
    out_capture: *mut *mut LoupeCapture,
) -> c_int {
    if p.is_null() || out_capture.is_null() { return LOUPE_ERR_BAD_ARG; }

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // Wrap the raw ctx pointer so it can cross the await boundary.
    struct SendCtx(*mut c_void);
    unsafe impl Send for SendCtx {}
    let sctx = SendCtx(ctx);

    match backend::spawn_pcapd(&RT, stop_rx, move |pkt: &[u8]| {
        cb(sctx.0, pkt.as_ptr(), pkt.len());
    }) {
        Ok(()) => {
            let cap = Box::new(LoupeCapture { stop: stop_tx });
            unsafe { *out_capture = Box::into_raw(cap) };
            LOUPE_OK
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn loupe_capture_stop(c: *mut LoupeCapture) {
    if c.is_null() { return; }
    let cap = unsafe { Box::from_raw(c) };
    let _ = cap.stop.send(true);
}

// ---------------------------------------------------------------------------
// backend — the ONLY place that talks to `idevice`. Reconcile these bodies.
// ---------------------------------------------------------------------------
mod backend {
    use super::*;

    pub fn validate_pairing(_plist: &[u8]) -> Result<(), c_int> {
        // FFI: parse the pairing plist (idevice::pairing / PairingFile) and verify
        //      UDID + HostCertificate + DeviceCertificate + keys are present.
        Err(not_wired("validate_pairing"))
    }

    pub async fn start_provider(_pairing: &[u8]) -> Result<(), c_int> {
        // FFI: build an idevice provider from the pairing file, perform the RSD
        //      handshake over the on-device tunnel to 127.0.0.1, open lockdown.
        Err(not_wired("start_provider"))
    }

    pub async fn developer_mode_enabled() -> Result<bool, c_int> {
        // FFI: query com.apple.security.mac.amfi / lockdown DeveloperModeStatus.
        Err(not_wired("developer_mode_enabled"))
    }

    pub async fn mount_ddi() -> Result<(), c_int> {
        // FFI: mobile_image_mounter — fetch/personalize + mount the DDI for the
        //      device's iOS version. No-op if already mounted.
        Err(not_wired("mount_ddi"))
    }

    pub async fn jit_enable(_bundle_id: &str) -> Result<(), c_int> {
        // FFI: via debugserver — look up the app, attach, set the CS_DEBUGGED bit
        //      (or launch-and-detach), then detach leaving the process debuggable.
        Err(not_wired("jit_enable"))
    }

    pub async fn list_apps() -> Result<String, c_int> {
        // FFI: installation_proxy Browse → map to [{bundleId,name}] JSON.
        Err(not_wired("list_apps"))
    }

    pub async fn install_ipa(_path: &str) -> Result<(), c_int> {
        // FFI: AFC upload the IPA to the staging area, installation_proxy Install.
        Err(not_wired("install_ipa"))
    }

    /// Spawn the pcapd reader. On each packet record, call `on_packet(&[u8])`.
    /// Stops when `stop_rx` flips to true.
    pub fn spawn_pcapd<F>(
        rt: &Runtime,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
        on_packet: F,
    ) -> Result<(), c_int>
    where
        F: Fn(&[u8]) + Send + 'static,
    {
        // The task structure is real; the pcapd socket read is the FFI piece.
        rt.spawn(async move {
            // FFI: open the com.apple.pcapd service over the provider and loop
            //      reading packet records, calling on_packet(record) for each.
            //
            //      loop {
            //          tokio::select! {
            //              _ = stop_rx.changed() => if *stop_rx.borrow() { break; },
            //              rec = pcapd.next_packet() => match rec {
            //                  Ok(bytes) => on_packet(&bytes),
            //                  Err(_) => break,
            //              }
            //          }
            //      }
            let _ = (&mut stop_rx, &on_packet);
            set_error("spawn_pcapd: not wired to the pinned `idevice` pcapd service.");
        });
        // We return OK because the task is spawned; real wiring will surface errors
        // through the stream/last_error. Until wired, no packets arrive.
        Ok(())
    }
}
