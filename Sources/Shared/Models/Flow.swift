import Foundation

/// A single captured request/response.
///
/// Two sources feed this model:
/// - `.pcap`  — from pcapd. Metadata only. For HTTPS, `encrypted == true` and the
///              body/headers are absent. This is the read-only "see everything" layer.
/// - `.frida` — from an in-app Frida hook. Full decrypted payloads, editable/resendable.
///
/// For a focused app the store merges both: pcap supplies the timeline of "a flow
/// happened", frida supplies the editable plaintext.
struct Flow: Identifiable, Codable, Hashable, Sendable {
    enum Source: String, Codable, Sendable { case pcap, frida }

    let id: UUID
    /// The gadget-side correlation id (e.g. "pid-seq") when this flow came from a
    /// Frida hook. Used to match breakpoint resume/drop back to the paused request.
    var hookID: String?
    var ts: Date
    var bundleId: String?
    var source: Source

    // Connection / addressing
    var host: String            // SNI (pcap) or URL host (frida)
    var srcPort: Int?
    var dstPort: Int?

    // HTTP semantics (populated for frida; best-effort/none for pcap)
    var method: String?
    var url: String?
    var reqHeaders: [String: String]
    var reqBody: Data?
    var status: Int?
    var respHeaders: [String: String]
    var respBody: Data?

    // Byte/timing accounting (pcap fills these from packet sizes)
    var bytesOut: Int
    var bytesIn: Int
    var startedAt: Date
    var endedAt: Date?

    // Flags
    var encrypted: Bool         // true: ciphertext we cannot read (pcap HTTPS)
    var edited: Bool            // true: a rule or breakpoint mutated this flow

    init(
        id: UUID = UUID(),
        hookID: String? = nil,
        ts: Date = .now,
        bundleId: String? = nil,
        source: Source,
        host: String,
        srcPort: Int? = nil,
        dstPort: Int? = nil,
        method: String? = nil,
        url: String? = nil,
        reqHeaders: [String: String] = [:],
        reqBody: Data? = nil,
        status: Int? = nil,
        respHeaders: [String: String] = [:],
        respBody: Data? = nil,
        bytesOut: Int = 0,
        bytesIn: Int = 0,
        startedAt: Date = .now,
        endedAt: Date? = nil,
        encrypted: Bool = false,
        edited: Bool = false
    ) {
        self.id = id
        self.hookID = hookID
        self.ts = ts
        self.bundleId = bundleId
        self.source = source
        self.host = host
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.method = method
        self.url = url
        self.reqHeaders = reqHeaders
        self.reqBody = reqBody
        self.status = status
        self.respHeaders = respHeaders
        self.respBody = respBody
        self.bytesOut = bytesOut
        self.bytesIn = bytesIn
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.encrypted = encrypted
        self.edited = edited
    }

    /// Whether this flow can be edited/resent. Only decrypted frida flows qualify.
    var isEditable: Bool { source == .frida && !encrypted }

    var durationMS: Int? {
        guard let endedAt else { return nil }
        return Int(endedAt.timeIntervalSince(startedAt) * 1000)
    }

    var displayURL: String { url ?? host }

    /// Reconstruct a cURL command for out-of-app replay. Body is included when present.
    func asCurl() -> String {
        var parts = ["curl"]
        if let method, method.uppercased() != "GET" { parts.append("-X \(method.uppercased())") }
        for (k, v) in reqHeaders.sorted(by: { $0.key < $1.key }) {
            parts.append("-H \(shellQuote("\(k): \(v)"))")
        }
        if let reqBody, !reqBody.isEmpty {
            let body = String(data: reqBody, encoding: .utf8) ?? reqBody.base64EncodedString()
            parts.append("--data-raw \(shellQuote(body))")
        }
        parts.append(shellQuote(url ?? "https://\(host)"))
        return parts.joined(separator: " ")
    }

    private func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
