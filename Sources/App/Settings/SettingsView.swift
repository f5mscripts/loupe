import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            List {
                Section("Instrument") {
                    HStack {
                        Text("Hook status")
                        Spacer()
                        Text(statusText).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Button("Connect to focused app's gadget") { model.connectInstrument() }
                    Button("Disconnect") { model.frida.disconnect() }
                    LabeledContent("Gadget port", value: "\(GadgetConfig.port)")
                }

                Section("Pairing") {
                    Button("Re-pair (clear stored pairing file)", role: .destructive) {
                        PairingStore.shared.clear()
                        model.device.lastMessage = "Pairing cleared. Import a new file in Setup."
                    }
                }

                Section("About") {
                    LabeledContent("pcapd", value: "read-only sniffer")
                    Text("pcapd shows every flow but HTTPS stays ciphertext. Editing and resending happen through the in-app Frida hook, which sits above TLS. On stock iOS only your own apps or apps you re-signed with the gadget can be instrumented.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Scope") {
                    Label("Authorized use only — your own apps/devices or systems you may test.",
                          systemImage: "checkmark.shield")
                        .font(.footnote)
                }
            }
            .navigationTitle("Settings")
        }
    }

    private var statusText: String {
        switch model.frida.status {
        case .disconnected: "disconnected"
        case .connecting:   "connecting…"
        case .connected(let pid): "connected (pid \(pid))"
        case .error(let m): "error: \(m)"
        }
    }
}
