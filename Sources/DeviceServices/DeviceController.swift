import Foundation
import Observation

/// Owns the provider handle and drives the setup sequence (M1) + JIT (M2) + install.
/// The provider is an opaque Rust handle; this class is its sole owner and frees it.
@MainActor
@Observable
final class DeviceController {

    private(set) var prereqs = Prerequisites()
    private(set) var installedApps: [AppProfile] = []
    var lastMessage: String?

    // M1: real pairing-file validation via the idevice FFI.
    var pairingValid: PrereqState = .unknown
    var pairingIdentifier: String?

    /// Validate + store an RP pairing file. Real: parses via idevice's RpPairingFile.
    func validatePairingFile(_ data: Data) async {
        pairingValid = .inProgress
        pairingIdentifier = nil
        do {
            try PairingStore.shared.importPairing(data)           // validates (FFI) + stores
            let id = await runOffMain { DeviceBridge.shared.pairingIdentifier() }
            pairingIdentifier = id
            pairingValid = .ok
            lastMessage = "Pairing file valid. Identifier: \(id ?? "—")"
        } catch {
            pairingValid = .failed(error.localizedDescription)
            lastMessage = "Pairing invalid: \(error.localizedDescription)"
        }
    }

    // nonisolated(unsafe): all real access is on the main actor, but `deinit` is
    // nonisolated and must free the handle. We take responsibility for that one use.
    nonisolated(unsafe) private var provider: OpaquePointer?

    var isReady: Bool { prereqs.allReady && provider != nil }

    deinit {
        if let p = provider { DeviceBridge.shared.freeProvider(p) }
    }

    // MARK: - M1: pairing → tunnel → DDI → developer mode

    func importPairing(_ data: Data) async {
        prereqs.paired = .inProgress
        do {
            try PairingStore.shared.importPairing(data)
            prereqs.paired = .ok
            await bringUpTunnel()
        } catch {
            prereqs.paired = .failed(error.localizedDescription)
        }
    }

    /// Full M1 bring-up using whatever pairing file is stored.
    func bringUp() async {
        guard let data = PairingStore.shared.load() else {
            prereqs.paired = .failed("No pairing file imported yet.")
            return
        }
        prereqs.paired = .ok
        await bringUpTunnel(existing: data)
    }

    private func bringUpTunnel(existing data: Data? = nil) async {
        let pairing = data ?? PairingStore.shared.load()
        guard let pairing else {
            prereqs.tunnel = .failed("Pairing file missing.")
            return
        }

        prereqs.tunnel = .inProgress
        do {
            if let p = provider { DeviceBridge.shared.freeProvider(p); provider = nil }
            let p = try await runOffMain { try DeviceBridge.shared.startProvider(pairing: pairing) }
            provider = p
            prereqs.tunnel = .ok
        } catch {
            prereqs.tunnel = .failed(error.localizedDescription)
            return
        }

        await mountDDIAndCheckDevMode()
    }

    private func mountDDIAndCheckDevMode() async {
        guard let p = provider else { return }

        prereqs.ddi = .inProgress
        do {
            try await runOffMain { try DeviceBridge.shared.mountDDI(p) }
            prereqs.ddi = .ok
        } catch {
            prereqs.ddi = .failed(error.localizedDescription)
        }

        prereqs.developerMode = .inProgress
        do {
            let on = try await runOffMain { try DeviceBridge.shared.developerModeEnabled(p) }
            prereqs.developerMode = on
                ? .ok
                : .failed("Developer Mode is off. Enable it in Settings → Privacy & Security.")
        } catch {
            prereqs.developerMode = .failed(error.localizedDescription)
        }
    }

    // MARK: - M2: JIT

    func enableJIT(bundleId: String) async -> Bool {
        guard let p = provider else {
            lastMessage = "Tunnel not up. Finish Setup first."
            return false
        }
        do {
            try await runOffMain { try DeviceBridge.shared.enableJIT(p, bundleId: bundleId) }
            lastMessage = "JIT enabled for \(bundleId)."
            return true
        } catch {
            lastMessage = "JIT failed: \(error.localizedDescription)"
            return false
        }
    }

    // MARK: - App listing / install

    func refreshApps() async {
        guard let p = provider else { return }
        do {
            let rows = try await runOffMain { try DeviceBridge.shared.listApps(p) }
            installedApps = rows.map { AppProfile(bundleId: $0.bundleId, name: $0.name) }
        } catch {
            lastMessage = "App list failed: \(error.localizedDescription)"
        }
    }

    func install(ipaPath: String) async -> Bool {
        guard let p = provider else { return false }
        do {
            try await runOffMain { try DeviceBridge.shared.installIPA(p, path: ipaPath) }
            lastMessage = "Installed \(ipaPath)."
            await refreshApps()
            return true
        } catch {
            lastMessage = "Install failed: \(error.localizedDescription)"
            return false
        }
    }

    /// Current provider for the capture layer (pcapd) to attach to.
    var providerHandle: OpaquePointer? { provider }

    // MARK: - util

    /// Run a throwing, blocking FFI call off the main actor.
    private func runOffMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await Task.detached(priority: .userInitiated) { try body() }.value
    }
}
