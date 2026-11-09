import SwiftUI

/// Setup, StikJIT workflow.
///
/// Loupe no longer owns pairing/tunnel/JIT — that's delegated to StikJIT (which
/// already does the on-device RSD tunnel + debugserver JIT robustly). Loupe focuses
/// on the Frida layer: it connects to the in-app gadget over loopback. This screen
/// walks the prerequisites and surfaces the hook connection.
struct SetupView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            List {
                Section("How Loupe works now") {
                    Text("Loupe instruments a target app through an embedded Frida gadget and talks to it over the local loopback. JIT for the target is provided by **StikJIT** — Loupe does not pair or tunnel itself.")
                        .font(.callout)
                }

                Section("Prerequisites") {
                    step(1, "Enable JIT with StikJIT",
                         "Open StikJIT, import your pairing file there, and enable JIT for your target app. That gives Frida the runtime codegen it needs.")
                    step(2, "Target must carry the Frida gadget",
                         "Your own app (link FridaGadget) or a third-party app you re-signed with the gadget (see Tools/resign-with-gadget.sh). App Store apps you haven't instrumented cannot be hooked.")
                    step(3, "Launch the target, then connect below",
                         "The gadget loads interceptor.js at launch and opens a loopback listener on port \(GadgetConfig.port). Loupe connects to it.")
                }

                Section("Hook connection") {
                    HStack {
                        Image(systemName: hookGlyph).foregroundStyle(hookColor)
                        Text(hookStatusText)
                        Spacer()
                        if case .connecting = model.frida.status { ProgressView() }
                    }
                    if let t = model.store.focusedProfile {
                        Text("Target: \(t.name) (\(t.bundleId))").font(.caption.monospaced()).foregroundStyle(.secondary)
                    } else {
                        Text("No target selected — pick one in the Apps tab.").font(.caption).foregroundStyle(.secondary)
                    }
                    Button {
                        model.connectInstrument()
                    } label: { Label("Connect to target's gadget", systemImage: "scope") }
                        .disabled(model.store.focusedProfile?.canInstrument != true)
                    if case .connected = model.frida.status {
                        Button(role: .destructive) { model.frida.disconnect() } label: {
                            Label("Disconnect", systemImage: "xmark.circle")
                        }
                    }
                }

                if let msg = model.device.lastMessage {
                    Section { Text(msg).font(.footnote).foregroundStyle(.secondary) }
                }

                Section {
                    Link(destination: URL(string: "https://github.com/StephenDev0/StikJIT")!) {
                        Label("Get StikJIT", systemImage: "arrow.up.right.square")
                    }
                } footer: {
                    Text("pcapd passive capture needs the on-device tunnel and isn't available in this build — the Frida hook already streams full decrypted request/response pairs, which is the see-and-edit layer anyway.")
                }
            }
            .navigationTitle("Setup")
        }
    }

    private func step(_ n: Int, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)")
                .font(.caption.bold()).foregroundStyle(.white)
                .frame(width: 22, height: 22).background(Circle().fill(.green))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.bold())
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var hookStatusText: String {
        switch model.frida.status {
        case .disconnected: "Not connected"
        case .connecting:   "Connecting…"
        case .connected(let pid): "Connected (pid \(pid))"
        case .error(let m): "Error: \(m)"
        }
    }
    private var hookGlyph: String {
        switch model.frida.status {
        case .connected: "checkmark.circle.fill"
        case .connecting: "circle.dotted"
        case .error: "xmark.circle.fill"
        case .disconnected: "circle"
        }
    }
    private var hookColor: Color {
        switch model.frida.status {
        case .connected: .green
        case .connecting: .orange
        case .error: .red
        case .disconnected: .secondary
        }
    }
}
