import Foundation

/// Evaluates rules against a flow and produces a mutated flow + a disposition.
/// Only ever called on editable (frida, non-encrypted) flows. pcap flows are
/// never passed here — the UI and store enforce that.
struct RuleEngine {

    enum Disposition: Equatable {
        case forward                 // send as-is (possibly mutated)
        case drop                    // do not deliver
        case mapLocal(Data)          // short-circuit with a canned body
        case breakpoint(side: Rule.Side) // pause for manual edit
    }

    struct Result {
        var flow: Flow
        var disposition: Disposition
        var firedRuleIDs: [UUID]
    }

    var rules: [Rule]

    /// Apply all enabled, in-scope rules for the given side, in `order`.
    func apply(to input: Flow, side: Rule.Side) -> Result {
        var flow = input
        var fired: [UUID] = []

        let scoped = rules
            .filter { $0.enabled && $0.side == side && inScope($0, flow) }
            .sorted { $0.order < $1.order }

        for rule in scoped {
            guard matches(rule, flow, side: side) else { continue }
            fired.append(rule.id)

            switch rule.action {
            case .breakpoint:
                return Result(flow: flow, disposition: .breakpoint(side: side), firedRuleIDs: fired)

            case .mapLocal:
                let body = Data(rule.replacement.utf8)
                flow.respBody = body
                flow.edited = true
                return Result(flow: flow, disposition: .mapLocal(body), firedRuleIDs: fired)

            case .headerSet:
                let (k, v) = splitHeader(rule.replacement)
                guard let k else { continue }
                if side == .req { flow.reqHeaders[k] = v } else { flow.respHeaders[k] = v }
                flow.edited = true

            case .bodyReplace:
                let data = (side == .req) ? flow.reqBody : flow.respBody
                guard let data, let text = String(data: data, encoding: .utf8) else { continue }
                let replaced = regexReplace(in: text, pattern: rule.pattern, template: rule.replacement)
                if replaced != text {
                    let out = Data(replaced.utf8)
                    if side == .req { flow.reqBody = out } else { flow.respBody = out }
                    flow.edited = true
                }
            }
        }

        return Result(flow: flow, disposition: .forward, firedRuleIDs: fired)
    }

    // MARK: - Matching

    private func inScope(_ rule: Rule, _ flow: Flow) -> Bool {
        if let b = rule.scopeBundleId, b != flow.bundleId { return false }
        if let h = rule.scopeHost, !glob(h, flow.host) { return false }
        return true
    }

    private func matches(_ rule: Rule, _ flow: Flow, side: Rule.Side) -> Bool {
        switch rule.matchType {
        case .always:
            return true
        case .hostGlob:
            return glob(rule.pattern, flow.host)
        case .urlRegex:
            return regexTest(rule.pattern, flow.url ?? flow.host)
        case .headerRegex:
            let headers = side == .req ? flow.reqHeaders : flow.respHeaders
            let joined = headers.map { "\($0.key): \($0.value)" }.joined(separator: "\n")
            return regexTest(rule.pattern, joined)
        case .bodyRegex:
            let data = side == .req ? flow.reqBody : flow.respBody
            guard let data, let text = String(data: data, encoding: .utf8) else { return false }
            return regexTest(rule.pattern, text)
        }
    }

    // MARK: - Regex / glob helpers

    private func regexTest(_ pattern: String, _ subject: String) -> Bool {
        guard !pattern.isEmpty,
              let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        else { return false }
        let range = NSRange(subject.startIndex..., in: subject)
        return re.firstMatch(in: subject, range: range) != nil
    }

    private func regexReplace(in subject: String, pattern: String, template: String) -> String {
        guard !pattern.isEmpty,
              let re = try? NSRegularExpression(pattern: pattern, options: [])
        else { return subject }
        let range = NSRange(subject.startIndex..., in: subject)
        return re.stringByReplacingMatches(in: subject, range: range, withTemplate: template)
    }

    /// Very small glob: `*` wildcard, case-insensitive. Good enough for host scoping.
    private func glob(_ pattern: String, _ subject: String) -> Bool {
        let escaped = NSRegularExpression.escapedPattern(for: pattern)
            .replacingOccurrences(of: "\\*", with: ".*")
        return regexTest("^\(escaped)$", subject)
    }

    private func splitHeader(_ s: String) -> (String?, String) {
        guard let idx = s.firstIndex(of: ":") else { return (nil, "") }
        let k = s[..<idx].trimmingCharacters(in: .whitespaces)
        let v = s[s.index(after: idx)...].trimmingCharacters(in: .whitespaces)
        return (k.isEmpty ? nil : k, v)
    }
}
