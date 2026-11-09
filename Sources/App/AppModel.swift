import Foundation
import Observation

/// Top-level app state. Owns every layer and wires them together.
@MainActor
@Observable
final class AppModel {
    let store = FlowStore()
    let device = DeviceController()
    let frida: FridaManager
    let pcapd: PcapdCapture

    /// One-time consent (see Ethics & Scope in the README).
    var consentAccepted: Bool {
        didSet { UserDefaults.standard.set(consentAccepted, forKey: "loupe.consent") }
    }

    init() {
        let store = self.store
        self.frida = FridaManager(store: store)
        self.pcapd = PcapdCapture(store: store)
        self.consentAccepted = UserDefaults.standard.bool(forKey: "loupe.consent")
        self.frida.onMessage = { [weak self] msg in self?.device.lastMessage = msg }
    }

    // MARK: - Capture control (M3)

    // Reads the observable store flag (PcapdCapture sets it on start/stop) so the
    // UI refreshes; pcapd.isRunning itself isn't observable.
    var isCapturing: Bool { store.isCapturing }

    func toggleCapture() {
        // pcapd passive capture needs the on-device tunnel, which Loupe no longer owns
        // (JIT/tunnel are delegated to StikJIT). The Frida hook already streams full
        // decrypted request/response pairs — that's the see-and-edit layer.
        device.lastMessage = "pcapd passive capture needs the on-device tunnel (not in this build). Connect the Frida hook instead — it streams full decrypted flows."
    }

    // MARK: - Instrument control (M4)

    /// Connect to the focused app's in-process gadget. Only valid for instrumented apps.
    func connectInstrument() {
        guard let p = store.focusedProfile, p.canInstrument else {
            device.lastMessage = "No instrumented target focused. Add/focus a target marked instrumented first."
            return
        }
        device.lastMessage = "Connecting to gadget at 127.0.0.1:\(GadgetConfig.port) for \(p.name)…"
        frida.connect()
    }
}
