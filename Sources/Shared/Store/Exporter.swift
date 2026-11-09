import Foundation

/// Export captured flows to HAR 1.2, per-flow cURL, and raw .pcap passthrough.
enum Exporter {

    /// HAR 1.2. Only flows with HTTP semantics (frida, or plaintext pcap) export
    /// meaningfully; encrypted pcap flows are emitted as entries with empty bodies.
    static func har(_ flows: [Flow]) -> Data {
        let entries: [[String: Any]] = flows.map { f in
            let reqHeaders = f.reqHeaders.map { ["name": $0.key, "value": $0.value] }
            let respHeaders = f.respHeaders.map { ["name": $0.key, "value": $0.value] }
            let reqBodyText = f.reqBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let respBodyText = f.respBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""

            return [
                "startedDateTime": iso(f.startedAt),
                "time": f.durationMS ?? 0,
                "request": [
                    "method": f.method ?? "GET",
                    "url": f.url ?? "https://\(f.host)",
                    "httpVersion": "HTTP/1.1",
                    "headers": reqHeaders,
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": f.reqBody?.count ?? 0,
                    "postData": reqBodyText.isEmpty ? NSNull() : [
                        "mimeType": f.reqHeaders["Content-Type"] ?? "application/octet-stream",
                        "text": reqBodyText
                    ]
                ] as [String: Any],
                "response": [
                    "status": f.status ?? 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": respHeaders,
                    "cookies": [],
                    "content": [
                        "size": f.respBody?.count ?? 0,
                        "mimeType": f.respHeaders["Content-Type"] ?? "application/octet-stream",
                        "text": respBodyText
                    ] as [String: Any],
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": f.respBody?.count ?? 0
                ] as [String: Any],
                "cache": [:],
                "timings": ["send": 0, "wait": f.durationMS ?? 0, "receive": 0],
                "_source": f.source.rawValue,
                "_encrypted": f.encrypted,
                "_edited": f.edited,
                "_bundleId": f.bundleId ?? ""
            ]
        }

        let root: [String: Any] = [
            "log": [
                "version": "1.2",
                "creator": ["name": "Loupe", "version": "1.0"],
                "entries": entries
            ]
        ]
        return (try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted]))
            ?? Data("{}".utf8)
    }

    static func curl(_ flow: Flow) -> String { flow.asCurl() }

    private static func iso(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: d)
    }
}
