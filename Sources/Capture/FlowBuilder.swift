import Foundation

/// Coalesces parsed packets into `Flow` records keyed by TCP/UDP 5-tuple.
/// pcapd flows carry metadata only: host (SNI/Host), ports, byte counts, timing,
/// and the `encrypted` flag. No payloads — that's the Frida layer's job.
actor FlowBuilder {

    private struct Key: Hashable {
        let a: String, b: String, pa: Int, pb: Int, proto: UInt8
        /// Direction-insensitive key so request/response packets land on one flow.
        init(_ p: PacketParser.Parsed) {
            if (p.srcIP, p.srcPort) <= (p.dstIP, p.dstPort) {
                a = p.srcIP; pa = p.srcPort; b = p.dstIP; pb = p.dstPort
            } else {
                a = p.dstIP; pa = p.dstPort; b = p.srcIP; pb = p.srcPort
            }
            proto = p.proto
        }
    }

    private var open: [Key: Flow] = [:]
    private let idleTimeout: TimeInterval = 15

    /// Feed one parsed packet. Returns a flow to publish when it's new or updated.
    func ingest(_ p: PacketParser.Parsed, bytes: Int, bundleId: String?) -> Flow {
        let key = Key(p)
        let host = p.sni ?? p.httpHost ?? p.dstIP
        let now = Date.now

        if var existing = open[key] {
            existing.bytesOut += (p.dstPort == existing.dstPort) ? bytes : 0
            existing.bytesIn += (p.srcPort == existing.dstPort) ? bytes : 0
            existing.endedAt = now
            if existing.host == existing.dstIP, host != p.dstIP { existing.host = host } // upgrade IP→SNI
            open[key] = existing
            return existing
        }

        let flow = Flow(
            ts: now,
            bundleId: bundleId,
            source: .pcap,
            host: host,
            srcPort: p.srcPort,
            dstPort: p.dstPort,
            method: p.httpMethod,
            url: p.httpPath.map { path in
                let scheme = p.encrypted ? "https" : "http"
                return "\(scheme)://\(host)\(path)"
            },
            bytesOut: bytes,
            bytesIn: 0,
            startedAt: now,
            endedAt: now,
            encrypted: p.encrypted
        )
        open[key] = flow
        return flow
    }

    /// Evict idle flows (called periodically). Returns nothing; flows already published.
    func evictIdle() {
        let cutoff = Date.now.addingTimeInterval(-idleTimeout)
        open = open.filter { ($0.value.endedAt ?? $0.value.startedAt) > cutoff }
    }

    func reset() { open.removeAll() }
}
