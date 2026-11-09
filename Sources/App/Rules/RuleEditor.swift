import SwiftUI

struct RuleEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var rule: Rule
    let onSave: (Rule) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("General") {
                    TextField("Name", text: $rule.name)
                    Toggle("Enabled", isOn: $rule.enabled)
                }
                Section("Scope") {
                    TextField("Bundle id (blank = any)", text: Binding(
                        get: { rule.scopeBundleId ?? "" },
                        set: { rule.scopeBundleId = $0.isEmpty ? nil : $0 }))
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                    TextField("Host glob (blank = any, e.g. *.api.example.com)", text: Binding(
                        get: { rule.scopeHost ?? "" },
                        set: { rule.scopeHost = $0.isEmpty ? nil : $0 }))
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                }
                Section("Trigger") {
                    Picker("Side", selection: $rule.side) {
                        ForEach(Rule.Side.allCases, id: \.self) { Text($0.rawValue.uppercased()).tag($0) }
                    }
                    Picker("Match", selection: $rule.matchType) {
                        ForEach(Rule.MatchType.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    if rule.matchType != .always {
                        TextField("Pattern", text: $rule.pattern, axis: .vertical)
                            .font(.callout.monospaced()).autocorrectionDisabled()
                    }
                }
                Section("Action") {
                    Picker("Do", selection: $rule.action) {
                        ForEach(Rule.Action.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    if rule.action != .breakpoint {
                        TextField(replacementHint, text: $rule.replacement, axis: .vertical)
                            .font(.callout.monospaced()).autocorrectionDisabled()
                    } else {
                        Text("Pauses the matching flow so you can edit it, then Forward or Drop from the Rules tab.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Rule")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSave(rule); dismiss() }
                }
                ToolbarItem(placement: .cancelAction) { Button("Cancel") { dismiss() } }
            }
        }
    }

    private var replacementHint: String {
        switch rule.action {
        case .headerSet:   "Key: Value"
        case .bodyReplace: "Replacement (regex template, $1 etc.)"
        case .mapLocal:    "Canned response body (served for matches)"
        case .breakpoint:  ""
        }
    }
}
