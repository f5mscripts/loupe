import SwiftUI

/// Persistent bottom status bar: Paired • DDI • Tunnel • Target • Capturing.
struct StatusBarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 14) {
            pill("Paired", model.device.prereqs.paired.isOK)
            pill("DDI", model.device.prereqs.ddi.isOK)
            pill("Tunnel", model.device.prereqs.tunnel.isOK)

            Divider().frame(height: 14)

            HStack(spacing: 4) {
                Image(systemName: "target").font(.caption2)
                Text(model.store.focusedProfile?.name ?? "No target")
                    .lineLimit(1)
            }
            .foregroundStyle(model.store.focusedProfile == nil ? .secondary : .primary)

            Spacer()

            HStack(spacing: 4) {
                Circle()
                    .fill(model.isCapturing ? .red : .gray)
                    .frame(width: 7, height: 7)
                Text(model.isCapturing ? "Capturing" : "Idle")
            }
        }
        .font(.caption.monospaced())
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial)
        .overlay(Divider(), alignment: .top)
    }

    private func pill(_ label: String, _ ok: Bool) -> some View {
        HStack(spacing: 3) {
            Image(systemName: ok ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(ok ? .green : .secondary)
            Text(label)
        }
    }
}
