import Foundation

/// Parses a single raw IP packet (link-layer header already stripped by the pcapd
/// reader) into addressing + L7 hints. This is metadata only — it never decrypts.
///
/// What we extract:
/// - IPv4/IPv6 src/dst addresses
/// - TCP/UDP src/dst ports and payload bounds
/// - TLS ClientHello SNI (→ host, marks `encrypted = true`)
/// - Plaintext HTTP request line + Host header (port 80, marks `encrypted = false`)
struct PacketParser {

    struct Parsed {
        var srcIP: String
        var dstIP: String
        var proto: UInt8          // 6 = TCP, 17 = UDP
        var srcPort: Int
        var dstPort: Int
        var payload: ArraySlice<UInt8>
        var sni: String?          // from TLS ClientHello
        var httpHost: String?     // from plaintext HTTP
        var httpMethod: String?
        var httpPath: String?
        var encrypted: Bool
    }

    static func parse(_ bytes: [UInt8]) -> Parsed? {
        guard bytes.count >= 20 else { return nil }
        let version = bytes[0] >> 4
        if version == 4 { return parseIPv4(bytes) }
        if version == 6 { return parseIPv6(bytes) }
        return nil
    }

    // MARK: IPv4

    private static func parseIPv4(_ b: [UInt8]) -> Parsed? {
        let ihl = Int(b[0] & 0x0F) * 4
        guard ihl >= 20, b.count >= ihl + 4 else { return nil }
        let proto = b[9]
        let src = "\(b[12]).\(b[13]).\(b[14]).\(b[15])"
        let dst = "\(b[16]).\(b[17]).\(b[18]).\(b[19])"
        return parseL4(b, l4Offset: ihl, src: src, dst: dst, proto: proto)
    }

    // MARK: IPv6 (no extension-header walking; handles the common case)

    private static func parseIPv6(_ b: [UInt8]) -> Parsed? {
        guard b.count >= 40 else { return nil }
        let proto = b[6] // next header
        let src = ipv6String(Array(b[8..<24]))
        let dst = ipv6String(Array(b[24..<40]))
        return parseL4(b, l4Offset: 40, src: src, dst: dst, proto: proto)
    }

    private static func ipv6String(_ g: [UInt8]) -> String {
        stride(from: 0, to: 16, by: 2)
            .map { String(format: "%02x%02x", g[$0], g[$0 + 1]) }
            .joined(separator: ":")
    }

    // MARK: L4 + L7

    private static func parseL4(_ b: [UInt8], l4Offset: Int, src: String, dst: String, proto: UInt8) -> Parsed? {
        guard b.count >= l4Offset + 4 else { return nil }
        let srcPort = Int(b[l4Offset]) << 8 | Int(b[l4Offset + 1])
        let dstPort = Int(b[l4Offset + 2]) << 8 | Int(b[l4Offset + 3])

        var payloadOffset = l4Offset + 8 // UDP default
        if proto == 6 { // TCP
            guard b.count >= l4Offset + 13 else { return nil }
            let dataOffset = Int(b[l4Offset + 12] >> 4) * 4
            payloadOffset = l4Offset + dataOffset
        }
        guard payloadOffset <= b.count else { return nil }
        let payload = b[payloadOffset...]

        var p = Parsed(srcIP: src, dstIP: dst, proto: proto,
                       srcPort: srcPort, dstPort: dstPort, payload: payload,
                       sni: nil, httpHost: nil, httpMethod: nil, httpPath: nil,
                       encrypted: false)

        if dstPort == 443 || srcPort == 443 {
            p.encrypted = true
            p.sni = extractSNI(Array(payload))
        } else if dstPort == 80 || srcPort == 80 {
            parseHTTP(Array(payload), into: &p)
        }
        return p
    }

    // MARK: TLS ClientHello SNI

    /// Minimal TLS record/handshake walk to pull the SNI from a ClientHello.
    static func extractSNI(_ p: [UInt8]) -> String? {
        guard p.count > 43, p[0] == 0x16 else { return nil } // handshake record
        var i = 5                                            // skip record header
        guard i < p.count, p[i] == 0x01 else { return nil }  // ClientHello
        i += 4                                               // hs type + length(3)
        i += 2                                               // client version
        i += 32                                              // random
        guard i < p.count else { return nil }
        let sidLen = Int(p[i]); i += 1 + sidLen              // session id
        guard i + 2 <= p.count else { return nil }
        let csLen = Int(p[i]) << 8 | Int(p[i + 1]); i += 2 + csLen // cipher suites
        guard i < p.count else { return nil }
        let compLen = Int(p[i]); i += 1 + compLen            // compression
        guard i + 2 <= p.count else { return nil }
        let extTotal = Int(p[i]) << 8 | Int(p[i + 1]); i += 2
        let extEnd = min(i + extTotal, p.count)

        while i + 4 <= extEnd {
            let extType = Int(p[i]) << 8 | Int(p[i + 1])
            let extLen = Int(p[i + 2]) << 8 | Int(p[i + 3])
            i += 4
            guard i + extLen <= p.count else { return nil }
            if extType == 0x0000 { // server_name
                var j = i + 2                                // skip server_name_list len
                guard j + 3 <= p.count else { return nil }
                let nameType = p[j]; j += 1
                let nameLen = Int(p[j]) << 8 | Int(p[j + 1]); j += 2
                guard nameType == 0, j + nameLen <= p.count else { return nil }
                return String(bytes: p[j..<(j + nameLen)], encoding: .utf8)
            }
            i += extLen
        }
        return nil
    }

    // MARK: Plaintext HTTP

    private static func parseHTTP(_ p: [UInt8], into out: inout Parsed) {
        guard let text = String(bytes: p.prefix(2048), encoding: .utf8) else { return }
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let first = lines.first else { return }
        let parts = first.split(separator: " ")
        if parts.count >= 2, ["GET","POST","PUT","DELETE","HEAD","PATCH","OPTIONS"].contains(String(parts[0])) {
            out.httpMethod = String(parts[0])
            out.httpPath = String(parts[1])
        }
        for line in lines.dropFirst() {
            if line.lowercased().hasPrefix("host:") {
                out.httpHost = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                break
            }
        }
    }
}
