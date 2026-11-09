import Foundation
import Observation

/// Orchestrates the in-app Frida hook: connects to the gadget channel, pushes rules,
/// ingests full decrypted flows into the store, and handles breakpoints + repeater.
///
/// This is the "see + edit" layer. It only works against an INSTRUMENTED target
/// (your own app, or one re-signed with the gadget). Capture-only apps never reach
/// here — the UI gates on `AppProfile.canInstrument`.
@MainActor
@Observable
final class FridaManager {

    enum Status: Equatable { case disconnected, connecting, connected(pid: Int), error(String) }

    private(set) var status: Status = .disconnected
    private(set) var pausedFlows: [Flow] = []   // breakpoints awaiting user decision

    private let channel = HookChannel()
    private weak var store: FlowStore?
    private var resendContinuations: [String: CheckedContinuation<Flow, Never>] = [:]

    init(store: FlowStore) {
        self.store = store
        channel.onState = { [weak self] st in
            Task { @MainActor in self?.mapState(st) }
        }
        channel.onMessage = { [weak self] msg in
            Task { @MainActor in self?.handle(msg) }
        }
    }

    // MARK: - Lifecycle

    func connect() {
        status = .connecting
        channel.connect()
    }
    func disconnect() {
        channel.disconnect()
        status = .disconnected
    }

    /// Push the current rule set down to the hook (fast in-process match & replace /
    /// map-local / breakpoint arming). Host still re-evaluates for the UI record.
    func syncRules() {
        guard let store else { return }
        let payload = store.rules
            .filter { $0.scopeBundleId == nil || $0.scopeBundleId == store.focusedBundleId }
            .map(encodeRule)
        channel.send(["t": "rules", "rules": payload])
    }

    // MARK: - Breakpoints

    /// Forward a paused flow (optionally edited) back to the app.
    func resumeBreakpoint(_ flow: Flow, side: Rule.Side) {
        pausedFlows.removeAll { $0.id == flow.id }
        guard let hookID = flow.hookID else { return } // only gadget flows can resume
        channel.send([
            "t": "resume",
            "id": hookID,
            "side": side.rawValue,
            "flow": encodeFlow(flow)
        ])
    }

    func dropBreakpoint(_ flow: Flow) {
        pausedFlows.removeAll { $0.id == flow.id }
        guard let hookID = flow.hookID else { return }
        channel.send(["t": "drop", "id": hookID])
    }

    // MARK: - Repeater

    /// Re-issue a (possibly edited) request inside the app so auth/cookies/pinning
    /// carry over. Resolves with the response flow when the gadget replies.
    func resend(_ flow: Flow) async -> Flow {
        let id = UUID().uuidString
        channel.send([
            "t": "resend",
            "id": id,
            "method": flow.method ?? "GET",
            "url": flow.url ?? "https://\(flow.host)",
            "headers": flow.reqHeaders,
            "body": flow.reqBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        ])
        return await withCheckedContinuation { cont in
            resendContinuations[id] = cont
        }
    }

    // MARK: - Inbound dispatch

    private func mapState(_ st: HookChannel.State) {
        switch st {
        case .connecting: status = .connecting
        case .connected:  break // wait for hello to learn pid
        case .failed(let m): status = .error(m)
        case .idle: if case .connected = status { status = .disconnected }
        }
    }

    private func handle(_ msg: [String: Any]) {
        guard let t = msg["t"] as? String else { return }
        switch t {
        case "hello":
            let pid = msg["pid"] as? Int ?? 0
            status = .connected(pid: pid)
            syncRules()

        case "flow":
            if let flow = decodeFlow(msg) { store?.ingestFrida(flow) }

        case "paused":
            if let flow = decodeFlow(msg) { pausedFlows.append(flow) }

        case "resendResult":
            if let id = msg["id"] as? String, let cont = resendContinuations.removeValue(forKey: id) {
                cont.resume(returning: decodeResend(msg))
            }

        case "log":
            #if DEBUG
            print("[gadget] \(msg["msg"] ?? "")")
            #endif

        default: break
        }
    }

    // MARK: - Encode / decode (JSON ↔ model)

    private func encodeRule(_ r: Rule) -> [String: Any] {
        [
            "id": r.id.uuidString, "enabled": r.enabled, "side": r.side.rawValue,
            "scopeHost": r.scopeHost ?? "", "matchType": r.matchType.rawValue,
            "pattern": r.pattern, "action": r.action.rawValue, "replacement": r.replacement
        ]
    }

    private func encodeFlow(_ f: Flow) -> [String: Any] {
        [
            "id": f.id.uuidString, "host": f.host, "method": f.method ?? "GET",
            "url": f.url ?? "", "reqHeaders": f.reqHeaders,
            "reqBody": f.reqBody.flatMap { String(data: $0, encoding: .utf8) } ?? "",
            "status": f.status ?? 0, "respHeaders": f.respHeaders,
            "respBody": f.respBody.flatMap { String(data: $0, encoding: .utf8) } ?? "",
            "edited": f.edited
        ]
    }

    private func decodeFlow(_ m: [String: Any]) -> Flow? {
        let host = m["host"] as? String ?? "unknown"
        return Flow(
            hookID: m["id"] as? String,
            bundleId: m["bundleId"] as? String,
            source: .frida,
            host: host,
            method: m["method"] as? String,
            url: m["url"] as? String,
            reqHeaders: m["reqHeaders"] as? [String: String] ?? [:],
            reqBody: (m["reqBody"] as? String).flatMap { $0.isEmpty ? nil : Data($0.utf8) },
            status: (m["status"] as? Int).flatMap { $0 == 0 ? nil : $0 },
            respHeaders: m["respHeaders"] as? [String: String] ?? [:],
            respBody: (m["respBody"] as? String).flatMap { $0.isEmpty ? nil : Data($0.utf8) },
            encrypted: false,
            edited: m["edited"] as? Bool ?? false
        )
    }

    private func decodeResend(_ m: [String: Any]) -> Flow {
        Flow(
            source: .frida,
            host: "repeater",
            status: m["status"] as? Int,
            respHeaders: m["headers"] as? [String: String] ?? [:],
            respBody: (m["body"] as? String).map { Data($0.utf8) },
            edited: true
        )
    }
}
