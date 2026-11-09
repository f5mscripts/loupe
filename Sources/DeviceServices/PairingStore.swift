import Foundation

/// Imports, persists (app group) and validates the pairing file.
/// iOS 27 StikPair-style pairing files are property lists; we store the raw bytes.
struct PairingStore {
    static let shared = PairingStore()

    private let fileName = "pairing.plist"

    private var containerURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.loupe")
    }

    private var pairingURL: URL? {
        containerURL?.appendingPathComponent(fileName)
    }

    var hasPairing: Bool {
        guard let url = pairingURL else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }

    func load() -> Data? {
        guard let url = pairingURL else { return nil }
        return try? Data(contentsOf: url)
    }

    /// Store and validate a pairing file. Throws if invalid/expired.
    @discardableResult
    func importPairing(_ data: Data) throws -> Data {
        try DeviceBridge.shared.validatePairing(data)
        guard let url = pairingURL else {
            throw DeviceError.generic("App group container unavailable. Check the app group entitlement.")
        }
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return data
    }

    func clear() {
        guard let url = pairingURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
