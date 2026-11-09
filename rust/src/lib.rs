//! Loupe device-services FFI (idevice).
//!
//! Milestone 1: the native pipeline is real end-to-end for ONE capability —
//! parsing/validating the RemotePairing (RP) pairing file. The crate cross-compiles
//! into LoupeFFI.xcframework and links into the app. Remaining calls (tunnel, list
//! apps, JIT, pcapd) are honest `not_wired` stubs filled in by later milestones.
//!
//! Reference: EscapeOS / StikJIT use this same `idevice` crate + RP tunnel.

use once_cell::sync::Lazy;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::Mutex;
use tokio::runtime::Runtime;

use idevice::remote_pairing::RpPairingFile;

// ---- status codes (kept in sync with LoupeStatus / DeviceError in Swift) --------
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

static RT: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("tokio runtime"));
static LAST_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
static LAST_IDENTIFIER: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

fn set_error(msg: impl Into<String>) {
    if let Ok(mut e) = LAST_ERROR.lock() { *e = msg.into(); }
}
fn not_wired(what: &str) -> c_int {
    set_error(format!("{what}: not wired yet (later milestone)."));
    LOUPE_ERR_NOT_WIRED
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() { return None; }
    CStr::from_ptr(p).to_str().ok()
}

fn ret_cstring(store: &Mutex<String>) -> *const c_char {
    thread_local! {
        static BUF: std::cell::RefCell<CString> = std::cell::RefCell::new(CString::new("").unwrap());
    }
    let s = store.lock().map(|g| g.clone()).unwrap_or_default();
    BUF.with(|b| {
        *b.borrow_mut() = CString::new(s).unwrap_or_default();
        b.borrow().as_ptr()
    })
}

#[no_mangle]
pub extern "C" fn loupe_init() -> c_int {
    Lazy::force(&RT);
    LOUPE_OK
}

#[no_mangle]
pub extern "C" fn loupe_last_error() -> *const c_char { ret_cstring(&LAST_ERROR) }

/// After a successful loupe_pairing_validate, returns the RP pairing file's
/// identifier (a device/pair UUID). Empty until a file has been validated.
#[no_mangle]
pub extern "C" fn loupe_pairing_identifier() -> *const c_char { ret_cstring(&LAST_IDENTIFIER) }

// ---- M1: real pairing-file validation -------------------------------------------

/// Parse + validate an RP pairing file (plist bytes: public_key/private_key/
/// identifier/alt_irk). Returns LOUPE_OK and stashes the identifier on success.
#[no_mangle]
pub extern "C" fn loupe_pairing_validate(bytes: *const u8, len: usize) -> c_int {
    if bytes.is_null() || len == 0 {
        set_error("pairing_validate: empty buffer");
        return LOUPE_ERR_BAD_ARG;
    }
    let data = unsafe { std::slice::from_raw_parts(bytes, len) };
    match RpPairingFile::from_bytes(data) {
        Ok(pf) => {
            if let Ok(mut id) = LAST_IDENTIFIER.lock() {
                *id = pf.identifier().to_string();
            }
            set_error("");
            LOUPE_OK
        }
        Err(e) => {
            set_error(format!("Not a valid RP pairing file: {e}"));
            LOUPE_ERR_PAIRING
        }
    }
}

// ---- opaque handles (kept for ABI stability; wired in later milestones) ---------

pub struct LoupeProvider { _p: Vec<u8> }
pub struct LoupeCapture { _stop: tokio::sync::watch::Sender<bool> }

#[no_mangle]
pub extern "C" fn loupe_provider_start(
    pairing_bytes: *const u8, pairing_len: usize, out_provider: *mut *mut LoupeProvider,
) -> c_int {
    // M2: parse the RP file, run the remote-pairing handshake, stand up the TLS-PSK
    //     CDTunnel to the device, RSD check-in. For now, validate then report pending.
    if pairing_bytes.is_null() || pairing_len == 0 || out_provider.is_null() {
        return LOUPE_ERR_BAD_ARG;
    }
    let data = unsafe { std::slice::from_raw_parts(pairing_bytes, pairing_len) };
    if RpPairingFile::from_bytes(data).is_err() {
        set_error("provider_start: invalid pairing file");
        return LOUPE_ERR_PAIRING;
    }
    not_wired("provider_start (tunnel)")
}

#[no_mangle]
pub extern "C" fn loupe_provider_free(p: *mut LoupeProvider) {
    if !p.is_null() { unsafe { drop(Box::from_raw(p)) } }
}

#[no_mangle]
pub extern "C" fn loupe_developer_mode_enabled(_p: *mut LoupeProvider, _out: *mut c_int) -> c_int {
    not_wired("developer_mode_enabled")
}
#[no_mangle]
pub extern "C" fn loupe_mount_ddi(_p: *mut LoupeProvider) -> c_int { not_wired("mount_ddi") }
#[no_mangle]
pub extern "C" fn loupe_jit_enable(_p: *mut LoupeProvider, _bundle_id: *const c_char) -> c_int {
    not_wired("jit_enable")
}
#[no_mangle]
pub extern "C" fn loupe_list_apps(_p: *mut LoupeProvider, _out_json: *mut *mut c_char) -> c_int {
    not_wired("list_apps")
}
#[no_mangle]
pub extern "C" fn loupe_install_ipa(_p: *mut LoupeProvider, _ipa_path: *const c_char) -> c_int {
    let _ = unsafe { cstr(_ipa_path) };
    not_wired("install_ipa")
}
#[no_mangle]
pub extern "C" fn loupe_string_free(s: *mut c_char) {
    if !s.is_null() { unsafe { drop(CString::from_raw(s)) } }
}

pub type LoupePacketCb = extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize);

#[no_mangle]
pub extern "C" fn loupe_capture_start(
    _p: *mut LoupeProvider, _cb: LoupePacketCb, _ctx: *mut c_void, _out: *mut *mut LoupeCapture,
) -> c_int {
    not_wired("capture_start (pcapd)")
}
#[no_mangle]
pub extern "C" fn loupe_capture_stop(c: *mut LoupeCapture) {
    if !c.is_null() { unsafe { drop(Box::from_raw(c)) } }
}
