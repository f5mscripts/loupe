import Foundation

/// An ordered, toggleable interception rule, scoped to an app profile.
/// Rules are evaluated by `RuleEngine` against frida flows (the only editable source).
struct Rule: Identifiable, Codable, Hashable, Sendable {
    enum Side: String, Codable, CaseIterable, Sendable { case req, resp }

    enum MatchType: String, Codable, CaseIterable, Sendable {
        case urlRegex       // regex against the full URL
        case hostGlob       // glob against host
        case headerRegex    // regex against "Key: Value" lines
        case bodyRegex      // regex against the (utf8) body
        case always         // matches every flow in scope
    }

    enum Action: String, Codable, CaseIterable, Sendable {
        case headerSet      // set/replace a header (replacement = "Key: Value")
        case bodyReplace    // regex-replace within the body (pattern/replacement)
        case mapLocal       // serve a canned response body for matching requests
        case breakpoint     // pause the flow for manual edit, then forward/drop
    }

    let id: UUID
    var enabled: Bool
    var name: String

    // Scope: nil means "any". A rule applies only when both match (or are nil).
    var scopeBundleId: String?
    var scopeHost: String?

    var side: Side
    var matchType: MatchType
    var pattern: String          // meaning depends on matchType
    var action: Action
    var replacement: String      // meaning depends on action
    var order: Int               // lower runs first

    init(
        id: UUID = UUID(),
        enabled: Bool = true,
        name: String = "New rule",
        scopeBundleId: String? = nil,
        scopeHost: String? = nil,
        side: Side = .resp,
        matchType: MatchType = .urlRegex,
        pattern: String = "",
        action: Action = .bodyReplace,
        replacement: String = "",
        order: Int = 0
    ) {
        self.id = id
        self.enabled = enabled
        self.name = name
        self.scopeBundleId = scopeBundleId
        self.scopeHost = scopeHost
        self.side = side
        self.matchType = matchType
        self.pattern = pattern
        self.action = action
        self.replacement = replacement
        self.order = order
    }
}
