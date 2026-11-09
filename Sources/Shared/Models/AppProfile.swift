import Foundation

/// A per-app profile. `instrumented` is the key distinction:
/// - true  → own app or re-signed-with-gadget: see + edit + resend (frida).
/// - false → capture-only: pcapd metadata only, read-only.
struct AppProfile: Identifiable, Codable, Hashable, Sendable {
    var id: String { bundleId }

    let bundleId: String
    var name: String
    var instrumented: Bool
    var colorTag: ColorTag
    var jitEnabled: Bool
    var gadgetPresent: Bool

    enum ColorTag: String, Codable, CaseIterable, Sendable {
        case blue, green, orange, purple, red, gray
    }

    init(
        bundleId: String,
        name: String,
        instrumented: Bool = false,
        colorTag: ColorTag = .gray,
        jitEnabled: Bool = false,
        gadgetPresent: Bool = false
    ) {
        self.bundleId = bundleId
        self.name = name
        self.instrumented = instrumented
        self.colorTag = colorTag
        self.jitEnabled = jitEnabled
        self.gadgetPresent = gadgetPresent
    }

    /// An app is instrumentable on stock iOS only if it's your own or carries the gadget.
    var canInstrument: Bool { gadgetPresent || instrumented }
}
