import Foundation

/// Tri-state for each setup prerequisite, surfaced in the Setup tab + status bar.
enum PrereqState: Equatable {
    case unknown
    case inProgress
    case ok
    case failed(String)

    var isOK: Bool { if case .ok = self { return true } else { return false } }

    var glyph: String {
        switch self {
        case .unknown:    return "circle"
        case .inProgress: return "circle.dotted"
        case .ok:         return "checkmark.circle.fill"
        case .failed:     return "xmark.circle.fill"
        }
    }
}

struct Prerequisites: Equatable {
    var paired: PrereqState = .unknown
    var tunnel: PrereqState = .unknown
    var ddi: PrereqState = .unknown
    var developerMode: PrereqState = .unknown

    var allReady: Bool {
        paired.isOK && tunnel.isOK && ddi.isOK && developerMode.isOK
    }
}
