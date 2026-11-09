import SwiftUI
import UIKit

/// Flow detail: method/URL/headers/body with JSON / raw / hex views. For editable
/// (frida) flows, offers "Send to Repeater" and copy-as-cURL. pcap flows are
/// explicitly shown as read-only, with encrypted bodies flagged.
struct FlowDetailView: View {
    @Environment(AppModel.self) private var model
    let flow: Flow
    @State private var showCopied = false

    var body: some View {
        List {
            Section {
                labeled("Source", flow.source == .frida ? "Frida (decrypted, editable)" : "pcapd (metadata, read-only)")
                labeled("Host", flow.host)
                if let url = flow.url { labeled("URL", url) }
                if let m = flow.method { labeled("Method", m) }
                if let s = flow.status { labeled("Status", "\(s)") }
                if let ms = flow.durationMS { labeled("Duration", "\(ms) ms") }
                labeled("Bytes", "↑\(flow.bytesOut)  ↓\(flow.bytesIn)")
                if flow.encrypted {
                    Label("Encrypted — pcapd cannot read this body. Instrument the app to see it.",
                          systemImage: "lock.fill")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            if !flow.reqHeaders.isEmpty {
                Section("Request headers") { headerList(flow.reqHeaders) }
            }
            if let body = flow.reqBody {
                Section("Request body") { BodyView(data: body) }
            }
            if !flow.respHeaders.isEmpty {
                Section("Response headers") { headerList(flow.respHeaders) }
            }
            if let body = flow.respBody {
                Section("Response body") { BodyView(data: body) }
            }

            Section {
                Button {
                    UIPasteboard.general.string = flow.asCurl()
                    showCopied = true
                } label: { Label("Copy as cURL", systemImage: "terminal") }

                if flow.isEditable {
                    NavigationLink {
                        RepeaterView(seed: flow)
                    } label: { Label("Send to Repeater", systemImage: "arrow.triangle.2.circlepath") }
                } else {
                    Label("Read-only flow — resend needs an instrumented target.",
                          systemImage: "lock")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle(flow.method ?? flow.host)
        .navigationBarTitleDisplayMode(.inline)
        .alert("Copied cURL", isPresented: $showCopied) { Button("OK", role: .cancel) {} }
    }

    private func labeled(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).font(.caption.monospaced()).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
    }
    private func headerList(_ h: [String: String]) -> some View {
        ForEach(h.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
            VStack(alignment: .leading) {
                Text(k).font(.caption.bold().monospaced())
                Text(v).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
    }
}

/// Body viewer: JSON (pretty), raw UTF-8, or hex. Monospaced.
struct BodyView: View {
    let data: Data
    enum Mode: String, CaseIterable { case json = "JSON", raw = "Raw", hex = "Hex" }
    @State private var mode: Mode = .json

    var body: some View {
        VStack(alignment: .leading) {
            Picker("", selection: $mode) {
                ForEach(Mode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented)

            ScrollView(.horizontal) {
                Text(rendered)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 320)
        }
    }

    private var rendered: String {
        switch mode {
        case .raw: return String(data: data, encoding: .utf8) ?? "<\(data.count) bytes, not UTF-8>"
        case .hex: return hexDump(data)
        case .json:
            if let obj = try? JSONSerialization.jsonObject(with: data),
               let pretty = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
               let s = String(data: pretty, encoding: .utf8) {
                return s
            }
            return String(data: data, encoding: .utf8) ?? "<not JSON>"
        }
    }

    private func hexDump(_ d: Data) -> String {
        let bytes = [UInt8](d)
        var out = ""
        for off in stride(from: 0, to: bytes.count, by: 16) {
            let chunk = bytes[off..<min(off + 16, bytes.count)]
            let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
                .padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = chunk.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
            let offset = String(format: "%08x", off)
            out += "\(offset)  \(hex)  \(ascii)\n"
        }
        return out
    }
}
