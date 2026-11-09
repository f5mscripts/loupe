import Foundation

/// The FridaGadget configuration we ship next to the dylib. The gadget loads
/// `interceptor.js` at launch; the script opens its own loopback listener on
/// `port`, which Loupe connects to. Keep `port` in sync with interceptor.js.
enum GadgetConfig {
    static let host = "127.0.0.1"
    static let port: UInt16 = 27850

    /// The JSON written as `FridaGadget.config.so.json` (next to the dylib). This
    /// uses the gadget's "script" interaction so our interceptor loads at launch
    /// with no external frida client required.
    static func configJSON(scriptPath: String = "@executable_path/Frameworks/interceptor.js") -> String {
        """
        {
          "interaction": {
            "type": "script",
            "path": "\(scriptPath)",
            "on_change": "reload"
          }
        }
        """
    }
}
