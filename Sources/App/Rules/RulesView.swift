import SwiftUI

/// M5: ordered, toggleable rule list (match & replace, map-local, breakpoint, header set),
/// scoped per app profile, persisted. Also surfaces live breakpoints awaiting a decision.
struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var editing: Rule?

    var body: some View {
        NavigationStack {
            List {
                if !model.frida.pausedFlows.isEmpty {
                    Section("Paused (breakpoints)") {
                        ForEach(model.frida.pausedFlows) { flow in
                            BreakpointRow(flow: flow)
                        }
                    }
                }

                Section {
                    ForEach(model.store.rules.sorted(by: { $0.order < $1.order })) { rule in
                        Button { editing = rule } label: { RuleRow(rule: rule) }
                            .buttonStyle(.plain)
                    }
                    .onDelete { idx in
                        let sorted = model.store.rules.sorted(by: { $0.order < $1.order })
                        let ids = idx.map { sorted[$0].id }
                        model.store.rules.removeAll { ids.contains($0.id) }
                        model.frida.syncRules()
                    }
                    .onMove { from, to in
                        var sorted = model.store.rules.sorted(by: { $0.order < $1.order })
                        sorted.move(fromOffsets: from, toOffset: to)
                        for (i, var r) in sorted.enumerated() { r.order = i; upsert(r) }
                        model.frida.syncRules()
                    }
                } header: { Text("Rules — evaluated top to bottom") }
            }
            .navigationTitle("Rules")
            .toolbar {
                EditButton()
                Button {
                    let r = Rule(name: "Rule \(model.store.rules.count + 1)",
                                 scopeBundleId: model.store.focusedBundleId,
                                 order: model.store.rules.count)
                    model.store.rules.append(r)
                    editing = r
                } label: { Image(systemName: "plus") }
            }
            .sheet(item: $editing) { rule in
                RuleEditor(rule: rule) { updated in
                    upsert(updated); model.frida.syncRules()
                }
            }
        }
    }

    private func upsert(_ r: Rule) {
        if let i = model.store.rules.firstIndex(where: { $0.id == r.id }) { model.store.rules[i] = r }
        else { model.store.rules.append(r) }
    }
}

private struct RuleRow: View {
    @Environment(AppModel.self) private var model
    let rule: Rule
    var body: some View {
        HStack {
            Toggle("", isOn: Binding(
                get: { rule.enabled },
                set: { v in var r = rule; r.enabled = v
                    if let i = model.store.rules.firstIndex(where: { $0.id == r.id }) { model.store.rules[i] = r }
                    model.frida.syncRules()
                }
            )).labelsHidden()
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.name).font(.headline)
                Text("\(rule.side.rawValue.uppercased()) · \(rule.matchType.rawValue) → \(rule.action.rawValue)")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

private struct BreakpointRow: View {
    @Environment(AppModel.self) private var model
    let flow: Flow
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(flow.displayURL).font(.caption.monospaced()).lineLimit(1)
            HStack {
                Button("Forward") { model.frida.resumeBreakpoint(flow, side: flow.status == nil ? .req : .resp) }
                    .buttonStyle(.borderedProminent)
                Button("Drop", role: .destructive) { model.frida.dropBreakpoint(flow) }
                    .buttonStyle(.bordered)
                NavigationLink("Edit") { FlowDetailView(flow: flow) }
            }.font(.caption)
        }
    }
}
