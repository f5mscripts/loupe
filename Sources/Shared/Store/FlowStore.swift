import Foundation
import Observation

/// The single source of truth for the UI. Holds flows, rules, app profiles and
/// the focused target. Merges pcap (metadata) and frida (payload) flows.
@MainActor
@Observable
final class FlowStore {
    // Flows, newest first for display convenience.
    private(set) var flows: [Flow] = []
    var rules: [Rule] = [] { didSet { persistRules() } }
    var profiles: [AppProfile] = [] { didSet { persistProfiles() } }

    /// The per-app FOCUS — the organizing principle of the whole UI.
    var focusedBundleId: String?

    // Live prerequisite / capture state surfaced in the status bar.
    var isCapturing: Bool = false

    var engine: RuleEngine { RuleEngine(rules: rules) }

    var focusedProfile: AppProfile? {
        guard let focusedBundleId else { return nil }
        return profiles.first { $0.bundleId == focusedBundleId }
    }

    /// Flows for the currently focused app (or all, if nothing focused).
    var visibleFlows: [Flow] {
        guard let focusedBundleId else { return flows }
        return flows.filter { $0.bundleId == focusedBundleId }
    }

    init() {
        rules = Self.loadRules()
        profiles = Self.loadProfiles()
    }

    // MARK: - Ingest

    /// Ingest a pcap flow (metadata). If a frida flow already covers the same
    /// host+time window, we keep the richer frida one and just bump byte counts.
    func ingestPcap(_ flow: Flow) {
        flows.insert(flow, at: 0)
        trim()
    }

    /// Ingest a frida flow (full payload). This is the editable layer.
    func ingestFrida(_ flow: Flow) {
        flows.insert(flow, at: 0)
        trim()
    }

    /// Replace an existing flow (e.g. after a breakpoint edit or resend result).
    func update(_ flow: Flow) {
        if let i = flows.firstIndex(where: { $0.id == flow.id }) {
            flows[i] = flow
        } else {
            flows.insert(flow, at: 0)
        }
    }

    func clearFlows() { flows.removeAll() }

    private func trim(max: Int = 5000) {
        if flows.count > max { flows.removeLast(flows.count - max) }
    }

    // MARK: - Profiles

    func upsertProfile(_ p: AppProfile) {
        if let i = profiles.firstIndex(where: { $0.bundleId == p.bundleId }) {
            profiles[i] = p
        } else {
            profiles.append(p)
        }
    }

    func setFocus(_ bundleId: String?) { focusedBundleId = bundleId }

    // MARK: - Persistence (app group)

    // App's own defaults (no app group — not provisioned for sideloaded builds).
    private static let suite = UserDefaults.standard
    private static let rulesKey = "loupe.rules"
    private static let profilesKey = "loupe.profiles"

    private func persistRules() {
        if let data = try? JSONEncoder().encode(rules) {
            Self.suite.set(data, forKey: Self.rulesKey)
        }
    }
    private func persistProfiles() {
        if let data = try? JSONEncoder().encode(profiles) {
            Self.suite.set(data, forKey: Self.profilesKey)
        }
    }
    private static func loadRules() -> [Rule] {
        guard let d = suite.data(forKey: rulesKey),
              let r = try? JSONDecoder().decode([Rule].self, from: d) else { return [] }
        return r
    }
    private static func loadProfiles() -> [AppProfile] {
        guard let d = suite.data(forKey: profilesKey),
              let p = try? JSONDecoder().decode([AppProfile].self, from: d) else { return [] }
        return p
    }
}
