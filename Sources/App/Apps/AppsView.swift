import SwiftUI

/// App picker: list installed apps, tag instrumented vs capture-only, set FOCUS,
/// enable JIT (M2), and connect the instrument (M4).
struct AppsView: View {
    @Environment(AppModel.self) private var model

    private var apps: [AppProfile] {
        // Merge discovered apps with saved profiles (keep instrument/jit flags).
        let saved = Dictionary(uniqueKeysWithValues: model.store.profiles.map { ($0.bundleId, $0) })
        return model.device.installedApps.map { saved[$0.bundleId] ?? $0 }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    var body: some View {
        NavigationStack {
            List {
                if apps.isEmpty {
                    ContentUnavailableView(
                        "No apps loaded",
                        systemImage: "square.grid.2x2",
                        description: Text("Bring up the tunnel in Setup, then refresh.")
                    )
                }
                ForEach(apps) { app in
                    AppRow(app: app)
                }
            }
            .navigationTitle("Apps")
            .toolbar {
                Button {
                    Task { await model.device.refreshApps() }
                } label: { Image(systemName: "arrow.clockwise") }
                .disabled(!model.device.isReady)
            }
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
                Circle().fill(tagColor).frame(width: 10, height: 10)
                VStack(alignment: .leading) {
                    Text(app.name).font(.headline)
                    Text(app.bundleId).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                if isFocused { Image(systemName: "target").foregroundStyle(.green) }
            }

            HStack(spacing: 6) {
                badge(app.canInstrument ? "Instrumented" : "Capture-only",
                      color: app.canInstrument ? .green : .gray)
                if app.jitEnabled { badge("JIT", color: .blue) }
                if app.gadgetPresent { badge("Gadget", color: .purple) }
            }

            HStack {
                Button(isFocused ? "Focused" : "Focus") {
                    model.store.setFocus(isFocused ? nil : app.bundleId)
                }
                .buttonStyle(.bordered)
                .disabled(isFocused)

                Button("Enable JIT") {
                    Task {
                        let ok = await model.device.enableJIT(bundleId: app.bundleId)
                        if ok {
                            var p = app; p.jitEnabled = true
                            model.store.upsertProfile(p)
                        }
                    }
                }
                .buttonStyle(.bordered)
                .disabled(!model.device.isReady)

                if app.canInstrument {
                    Button("Connect hook") {
                        model.store.setFocus(app.bundleId)
                        model.connectInstrument()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .font(.caption)
        }
        .padding(.vertical, 4)
        .swipeActions {
            Button(app.instrumented ? "Unmark" : "Mark instrumented") {
                var p = app; p.instrumented.toggle()
                model.store.upsertProfile(p)
            }.tint(.purple)
        }
    }

    private var tagColor: Color {
        switch app.colorTag {
        case .blue: .blue; case .green: .green; case .orange: .orange
        case .purple: .purple; case .red: .red; case .gray: .gray
        }
    }

    private func badge(_ t: String, color: Color) -> some View {
        Text(t)
            .font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
