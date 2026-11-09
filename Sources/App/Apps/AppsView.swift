import SwiftUI

/// App picker (StikJIT workflow).
///
/// Listing installed apps needs the on-device tunnel (not in this build), so you
/// add your target manually: its bundle id, and whether it's instrumented (your own
/// app, or re-signed with the gadget). FOCUS sets the active target; Connect opens
/// the Frida hook. JIT is handled by StikJIT, not here.
struct AppsView: View {
    @Environment(AppModel.self) private var model

    @State private var newBundleId = ""
    @State private var newName = ""
    @State private var newInstrumented = true

    private var apps: [AppProfile] {
        model.store.profiles.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    TextField("Bundle id (e.g. com.example.target)", text: $newBundleId)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                        .font(.callout.monospaced())
                    TextField("Display name", text: $newName)
                    Toggle("Instrumented (own app / re-signed with gadget)", isOn: $newInstrumented)
                    Button {
                        let id = newBundleId.trimmingCharacters(in: .whitespaces)
                        guard !id.isEmpty else { return }
                        var p = AppProfile(bundleId: id,
                                           name: newName.isEmpty ? id : newName,
                                           instrumented: newInstrumented,
                                           colorTag: .green)
                        p.gadgetPresent = newInstrumented
                        model.store.upsertProfile(p)
                        model.store.setFocus(id)
                        newBundleId = ""; newName = ""
                    } label: { Label("Add target", systemImage: "plus.circle.fill") }
                        .disabled(newBundleId.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: {
                    Text("Add a target")
                } footer: {
                    Text("Capture-only apps can't be added here — without the tunnel, Loupe only works with instrumented targets (the Frida layer). App Store apps you haven't re-signed cannot be hooked on stock iOS.")
                }

                Section("Targets") {
                    if apps.isEmpty {
                        Text("No targets yet. Add one above.").foregroundStyle(.secondary)
                    }
                    ForEach(apps) { app in AppRow(app: app) }
                        .onDelete { idx in
                            let ids = idx.map { apps[$0].bundleId }
                            model.store.profiles.removeAll { ids.contains($0.bundleId) }
                        }
                }
            }
            .navigationTitle("Apps")
        }
    }
}

private struct AppRow: View {
    @Environment(AppModel.self) private var model
    let app: AppProfile
    private var isFocused: Bool { model.store.focusedBundleId == app.bundleId }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle().fill(.green).frame(width: 10, height: 10)
                VStack(alignment: .leading) {
                    Text(app.name).font(.headline)
                    Text(app.bundleId).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                if isFocused { Image(systemName: "target").foregroundStyle(.green) }
            }
            HStack(spacing: 6) {
                badge(app.canInstrument ? "Instrumented" : "Not instrumented",
                      color: app.canInstrument ? .green : .gray)
            }
            HStack {
                Button(isFocused ? "Focused" : "Focus") {
                    model.store.setFocus(isFocused ? nil : app.bundleId)
                }.buttonStyle(.bordered).disabled(isFocused)

                if app.canInstrument {
                    Button("Connect hook") {
                        model.store.setFocus(app.bundleId)
                        model.connectInstrument()
                    }.buttonStyle(.borderedProminent)
                }
            }.font(.caption)
        }
        .padding(.vertical, 4)
    }

    private func badge(_ t: String, color: Color) -> some View {
        Text(t).font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2)).foregroundStyle(color).clipShape(Capsule())
    }
}
