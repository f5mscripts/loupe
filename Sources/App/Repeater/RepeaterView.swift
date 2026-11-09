import SwiftUI

/// M5 Repeater: clone a captured request, edit method/URL/headers/body, resend via
/// the injected hook (so auth/cookies/pinning carry over), show the live response.
struct RepeaterView: View {
    @Environment(AppModel.self) private var model

    @State private var method = "GET"
    @State private var url = ""
    @State private var headersText = ""
    @State private var bodyText = ""
    @State private var response: Flow?
    @State private var sending = false

    /// Optional seed from a flow detail "Send to Repeater".
    var seed: Flow? = nil

    private let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]

    var body: some View {
        NavigationStack {
            Form {
                Section("Request") {
                    Picker("Method", selection: $method) {
                        ForEach(methods, id: \.self) { Text($0) }
                    }
                    TextField("URL", text: $url, axis: .vertical)
                        .font(.callout.monospaced()).autocorrectionDisabled().textInputAutocapitalization(.never)
                    TextField("Headers (Key: Value per line)", text: $headersText, axis: .vertical)
                        .font(.caption.monospaced()).autocorrectionDisabled().lineLimit(3...8)
                    TextField("Body", text: $bodyText, axis: .vertical)
                        .font(.caption.monospaced()).autocorrectionDisabled().lineLimit(3...12)
                }

                Section {
                    Button {
                        Task { await send() }
                    } label: {
                        HStack {
                            Image(systemName: "paperplane.fill")
                            Text(sending ? "Sending…" : "Send via hook")
                            if sending { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(sending || !isInstrumented || url.isEmpty)

                    if !isInstrumented {
                        Label("Repeater needs an instrumented, connected target. Connect the hook in Apps.",
                              systemImage: "lock")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                if let response {
                    Section("Response") {
                        if let s = response.status { Text("Status \(s)").font(.headline) }
                        if let body = response.respBody { BodyView(data: body) }
                    }
                }
            }
            .navigationTitle("Repeater")
            .onAppear { if let seed { load(seed) } }
        }
    }

    private var isInstrumented: Bool {
        if case .connected = model.frida.status { return true }
        return false
    }

    private func load(_ f: Flow) {
        method = f.method ?? "GET"
        url = f.url ?? "https://\(f.host)"
        headersText = f.reqHeaders.map { "\($0.key): \($0.value)" }.joined(separator: "\n")
        bodyText = f.reqBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
    }

    private func send() async {
        sending = true; defer { sending = false }
        var headers: [String: String] = [:]
        for line in headersText.split(separator: "\n") {
            guard let i = line.firstIndex(of: ":") else { continue }
            headers[line[..<i].trimmingCharacters(in: .whitespaces)] =
                line[line.index(after: i)...].trimmingCharacters(in: .whitespaces)
        }
        let req = Flow(
            source: .frida, host: URL(string: url)?.host ?? url,
            method: method, url: url, reqHeaders: headers,
            reqBody: bodyText.isEmpty ? nil : Data(bodyText.utf8)
        )
        response = await model.frida.resend(req)
    }
}
