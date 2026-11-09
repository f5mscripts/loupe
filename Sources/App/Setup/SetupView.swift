import SwiftUI
import UniformTypeIdentifiers

/// M1: pairing import → tunnel → DDI → developer mode. M2 JIT lives in Apps.
struct SetupView: View {
    @Environment(AppModel.self) private var model
    @State private var showImporter = false

    var body: some View {
        NavigationStack {
            List {
                Section("Pairing") {
                    prereqRow("Pairing file", model.device.prereqs.paired)
                    Button {
                        showImporter = true
                    } label: {
                        Label(PairingStore.shared.hasPairing ? "Replace pairing file…" : "Import pairing file…",
                              systemImage: "square.and.arrow.down")
                    }
                    Text("Generate a pairing file on-device (StikPair-style) and import it here. Loupe stores it in the app group and re-pairs when it expires.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("On-device tunnel") {
                    prereqRow("Lockdown tunnel", model.device.prereqs.tunnel)
                    prereqRow("DeveloperDiskImage mounted", model.device.prereqs.ddi)
                    prereqRow("Developer Mode", model.device.prereqs.developerMode)
                    Button {
                        Task { await model.device.bringUp() }
                    } label: {
                        Label("Bring up tunnel", systemImage: "bolt.horizontal.circle")
                    }
                    .disabled(!PairingStore.shared.hasPairing)
                }

                if let msg = model.device.lastMessage {
                    Section { Text(msg).font(.footnote).foregroundStyle(.secondary) }
                }

                Section {
                    HStack {
                        Image(systemName: model.device.isReady ? "checkmark.seal.fill" : "hourglass")
                            .foregroundStyle(model.device.isReady ? .green : .orange)
                        Text(model.device.isReady ? "Ready. Go to Apps to pick a target." : "Complete the steps above.")
                    }
                }
            }
            .navigationTitle("Setup")
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .xml, .propertyList]) { result in
                handleImport(result)
            }
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        guard case .success(let url) = result else { return }
        let needsStop = url.startAccessingSecurityScopedResource()
        defer { if needsStop { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            model.device.lastMessage = "Could not read the selected file."
            return
        }
        Task { await model.device.importPairing(data) }
    }

    private func prereqRow(_ label: String, _ state: PrereqState) -> some View {
        HStack {
            Image(systemName: state.glyph)
                .foregroundStyle(color(for: state))
            Text(label)
            Spacer()
            if case .failed(let m) = state {
                Text(m).font(.caption2).foregroundStyle(.red).multilineTextAlignment(.trailing)
            } else if case .inProgress = state {
                ProgressView()
            }
        }
    }

    private func color(for s: PrereqState) -> Color {
        switch s {
        case .ok: .green
        case .failed: .red
        case .inProgress: .orange
        case .unknown: .secondary
        }
    }
}
