import Foundation
import Network

/// Newline-delimited JSON channel to the in-app gadget's listener (interceptor.js).
/// Loupe is the client; the injected script is the server. Both are on this device,
/// so we connect to 127.0.0.1:<gadget port> over loopback.
final class HookChannel {

    enum State: Equatable { case idle, connecting, connected, failed(String) }

    private var connection: NWConnection?
    private var buffer = Data()
    private let queue = DispatchQueue(label: "loupe.hookchannel")

    var onMessage: (([String: Any]) -> Void)?
    var onState: ((State) -> Void)?

    func connect(host: String = GadgetConfig.host, port: UInt16 = GadgetConfig.port) {
        onState?(.connecting)
        let conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: .tcp
        )
        connection = conn
        conn.stateUpdateHandler = { [weak self] st in
            switch st {
            case .ready:   self?.onState?(.connected); self?.receive()
            case .failed(let e): self?.onState?(.failed(e.localizedDescription))
            case .cancelled: self?.onState?(.idle)
            default: break
            }
        }
        conn.start(queue: queue)
    }

    func disconnect() { connection?.cancel(); connection = nil }

    func send(_ obj: [String: Any]) {
        guard let conn = connection,
              var data = try? JSONSerialization.data(withJSONObject: obj) else { return }
        data.append(0x0A) // newline
        conn.send(content: data, completion: .contentProcessed { _ in })
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.buffer.append(data)
                self.drainLines()
            }
            if error == nil && !isComplete { self.receive() }
            else { self.onState?(.idle) }
        }
    }

    private func drainLines() {
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = buffer[..<nl]
            buffer.removeSubrange(...nl)
            guard !line.isEmpty,
                  let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any]
            else { continue }
            onMessage?(obj)
        }
    }
}
