import Foundation
#if canImport(LoupeFFI)
import LoupeFFI   // the cbindgen header, vended by LoupeFFI.xcframework (build-rust.sh)
#endif

/// Errors surfaced by the Rust FFI, mapped from LOUPE_ERR_* codes.
enum DeviceError: Error, LocalizedError, Equatable {
    case badArg, pairing, tunnel, ddi, jit, pcapd, install, notWired, generic(String)

    var errorDescription: String? {
        switch self {
        case .badArg:   return "Invalid argument."
        case .pairing:  return "Pairing failed or the pairing file is invalid/expired."
        case .tunnel:   return "Could not establish the on-device lockdown tunnel."
        case .ddi:      return "Failed to mount the DeveloperDiskImage."
        case .jit:      return "JIT enablement failed (debugserver)."
        case .pcapd:    return "Packet capture (pcapd) failed to start."
        case .install:  return "App install failed."
        case .notWired: return "This device call isn't wired to the idevice backend yet (see rust/src/lib.rs)."
        case .generic(let m): return m
        }
    }
}

/// Low-level, Sendable-safe wrapper over the C ABI. Everything above this talks Swift.
///
/// When LoupeFFI isn't linked (e.g. editing on a machine without the xcframework),
/// calls throw `.notWired` so the app still builds and the UI degrades gracefully.
struct DeviceBridge {

    static let shared = DeviceBridge()
    private init() {
        #if canImport(LoupeFFI)
        loupe_init()
        #endif
    }

    // MARK: Error mapping

    #if canImport(LoupeFFI)
    private func map(_ code: Int32) -> DeviceError? {
        // C integer #defines import as Int; normalize both sides to Int.
        switch Int(code) {
        case Int(LOUPE_OK): return nil
        case Int(LOUPE_ERR_BAD_ARG): return .badArg
        case Int(LOUPE_ERR_PAIRING): return .pairing
        case Int(LOUPE_ERR_TUNNEL):  return .tunnel
        case Int(LOUPE_ERR_DDI):     return .ddi
        case Int(LOUPE_ERR_JIT):     return .jit
        case Int(LOUPE_ERR_PCAPD):   return .pcapd
        case Int(LOUPE_ERR_INSTALL): return .install
        case Int(LOUPE_ERR_NOT_WIRED): return .notWired
        default:
            return .generic(lastError())
        }
    }

    private func lastError() -> String {
        guard let c = loupe_last_error() else { return "Unknown device error." }
        return String(cString: c)
    }

    private func check(_ code: Int32) throws {
        if let e = map(code) { throw e }
    }
    #endif

    // MARK: Pairing / provider

    func validatePairing(_ data: Data) throws {
        #if canImport(LoupeFFI)
        try data.withUnsafeBytes { raw in
            try check(loupe_pairing_validate(raw.bindMemory(to: UInt8.self).baseAddress, UInt(data.count)))
        }
        #else
        throw DeviceError.notWired
        #endif
    }

    /// After a successful validatePairing, the RP pairing file's identifier (UUID).
    func pairingIdentifier() -> String? {
        #if canImport(LoupeFFI)
        guard let c = loupe_pairing_identifier() else { return nil }
        let s = String(cString: c)
        return s.isEmpty ? nil : s
        #else
        return nil
        #endif
    }

    /// Starts the tunnel/provider and returns an opaque handle. The caller owns it.
    /// `LoupeProvider` is an incomplete C struct, so Swift represents it as OpaquePointer.
    func startProvider(pairing data: Data) throws -> OpaquePointer {
        #if canImport(LoupeFFI)
        var provider: OpaquePointer?
        try data.withUnsafeBytes { raw in
            try check(loupe_provider_start(
                raw.bindMemory(to: UInt8.self).baseAddress, UInt(data.count), &provider))
        }
        guard let provider else { throw DeviceError.tunnel }
        return provider
        #else
        throw DeviceError.notWired
        #endif
    }

    func freeProvider(_ p: OpaquePointer) {
        #if canImport(LoupeFFI)
        loupe_provider_free(p)
        #endif
    }

    func developerModeEnabled(_ p: OpaquePointer) throws -> Bool {
        #if canImport(LoupeFFI)
        var out: Int32 = 0
        try check(loupe_developer_mode_enabled(p, &out))
        return out != 0
        #else
        throw DeviceError.notWired
        #endif
    }

    func mountDDI(_ p: OpaquePointer) throws {
        #if canImport(LoupeFFI)
        try check(loupe_mount_ddi(p))
        #else
        throw DeviceError.notWired
        #endif
    }

    // MARK: JIT

    func enableJIT(_ p: OpaquePointer, bundleId: String) throws {
        #if canImport(LoupeFFI)
        try check(loupe_jit_enable(p, bundleId))
        #else
        throw DeviceError.notWired
        #endif
    }

    // MARK: Installation proxy

    func listApps(_ p: OpaquePointer) throws -> [(bundleId: String, name: String)] {
        #if canImport(LoupeFFI)
        var out: UnsafeMutablePointer<CChar>?
        try check(loupe_list_apps(p, &out))
        guard let out else { return [] }
        defer { loupe_string_free(out) }
        let json = String(cString: out)
        let data = Data(json.utf8)
        struct Row: Decodable { let bundleId: String; let name: String }
        let rows = (try? JSONDecoder().decode([Row].self, from: data)) ?? []
        return rows.map { ($0.bundleId, $0.name) }
        #else
        throw DeviceError.notWired
        #endif
    }

    func installIPA(_ p: OpaquePointer, path: String) throws {
        #if canImport(LoupeFFI)
        try check(loupe_install_ipa(p, path))
        #else
        throw DeviceError.notWired
        #endif
    }
}
