import SwiftUI

/// Persistent bottom status bar (StikJIT workflow): Hook • Target • Flows.
struct StatusBarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 14) {
            HStack(spacing: 4) {
                Image(systemName: hookGlyph).foregroundStyle(hookColor).font(.caption2)
                Text(hookLabel)
            }

            Divider().frame(height: 14)

            HStack(spacing: 4) {
                Image(systemName: "target").font(.caption2)
                Text(model.store.focusedProfile?.name ?? "No target").lineLimit(1)
            }
            .foregroundStyle(model.store.focusedProfile == nil ? .secondary : .primary)

            Spacer()

            HStack(spacing: 4) {
                Image(systemName: "list.bullet.rectangle").font(.caption2)
                Text("\(model.store.visibleFlows.count) flows")
            }
        }
        .font(.caption.monospaced())
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial)
        .overlay(Divider(), alignment: .top)
    }

    private var hookLabel: String {
        switch model.frida.status {
        case .connected: "Hook ✓"
        case .connecting: "Hook …"
        case .error: "Hook ✗"
        case .disconnected: "Hook —"
        }
    }
    private var hookGlyph: String {
        switch model.frida.status {
        case .connected: "scope"
        default: "scope"
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
