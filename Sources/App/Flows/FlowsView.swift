import SwiftUI

/// Merged flow list for the focused app: pcapd (metadata, read-only) + frida (full).
struct FlowsView: View {
    @Environment(AppModel.self) private var model
    @State private var query = ""

    private var flows: [Flow] {
        let base = model.store.visibleFlows
        guard !query.isEmpty else { return base }
        return base.filter {
            $0.displayURL.localizedCaseInsensitiveContains(query) ||
            $0.host.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(flows) { flow in
                    NavigationLink { FlowDetailView(flow: flow) } label: { FlowRow(flow: flow) }
                }
            }
            .listStyle(.plain)
            .searchable(text: $query, prompt: "Filter host / URL")
            .navigationTitle("Flows")
            .toolbar {
                ToolbarItemGroup {
                    Button {
                        model.toggleCapture()
                    } label: {
                        Image(systemName: model.isCapturing ? "stop.circle.fill" : "record.circle")
                            .foregroundStyle(model.isCapturing ? .red : .green)
                    }
                    Menu {
                        Button("Clear flows", role: .destructive) { model.store.clearFlows() }
                        ShareLink(item: harFile(), preview: SharePreview("flows.har")) {
                            Label("Export HAR", systemImage: "square.and.arrow.up")
                        }
                    } label: { Image(systemName: "ellipsis.circle") }
                }
            }
            .overlay {
                if flows.isEmpty {
                    ContentUnavailableView(
                        model.store.focusedProfile == nil ? "Pick a target in Apps" : "No flows yet",
                        systemImage: "list.bullet.rectangle",
                        description: Text(model.isCapturing ? "Waiting for traffic…" : "Start capture or connect the hook.")
                    )
                }
            }
        }
    }

    private func harFile() -> URL {
        let data = Exporter.har(flows)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("flows.har")
        try? data.write(to: url)
        return url
    }
}

private struct FlowRow: View {
    let flow: Flow
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: flow.source == .frida ? "scope" : "dot.radiowaves.up.forward")
                .foregroundStyle(flow.source == .frida ? .green : .secondary)
                .font(.caption)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if let m = flow.method { Text(m).font(.caption2.bold().monospaced()) }
                    Text(flow.host).font(.subheadline).lineLimit(1)
                    if flow.edited { Image(systemName: "pencil.circle.fill").foregroundStyle(.orange).font(.caption2) }
                }
                Text(flow.displayURL).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                if let s = flow.status { Text("\(s)").font(.caption.bold()).foregroundStyle(statusColor(s)) }
                if flow.encrypted { Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.secondary) }
            }
        }
        .padding(.vertical, 2)
    }
    private func statusColor(_ s: Int) -> Color {
        switch s { case 200..<300: .green; case 300..<400: .blue; case 400..<600: .red; default: .secondary }
    }
}
