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
    }

    // MARK: - Capture control (M3)

    // Reads the observable store flag (PcapdCapture sets it on start/stop) so the
    // UI refreshes; pcapd.isRunning itself isn't observable.
    var isCapturing: Bool { store.isCapturing }

    func toggleCapture() {
        if pcapd.isRunning { pcapd.stop(); return }
        guard let provider = device.providerHandle else {
            device.lastMessage = "Finish Setup (tunnel) before capturing."
            return
        }
        do { try pcapd.start(provider: provider) }
        catch { device.lastMessage = "Capture failed: \(error.localizedDescription)" }
    }

    // MARK: - Instrument control (M4)

    /// Connect to the focused app's in-process gadget. Only valid for instrumented apps.
    func connectInstrument() {
        guard let p = store.focusedProfile, p.canInstrument else {
            device.lastMessage = "Focused app isn't instrumented. Re-sign it with the gadget, or pick your own app."
            return
        }
        frida.connect()
    }
}
