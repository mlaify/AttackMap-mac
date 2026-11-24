import Foundation

/// A composed attack chain (engine #248): findings linked step by step from
/// the attacker's starting capability to an impact, each step citing the
/// finding that enables it. Decoded from `attack_chains` in the report.
struct AttackChain: Decodable, Identifiable, Hashable {
    let id: String
    let impact: String
    let likelihood: Double
    let start: [String]
    let steps: [Step]

    struct Step: Decodable, Hashable {
        let ruleId: String
        let title: String
        let grants: [String]
        let file: String?
        let line: Int?
        let preconditionNotes: [String]

        enum CodingKeys: String, CodingKey {
            case title, grants, location
            case ruleId = "rule_id"
            case preconditionNotes = "precondition_notes"
        }
        private struct Location: Decodable { let file: String?; let line: Int? }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            ruleId = (try? c.decode(String.self, forKey: .ruleId)) ?? ""
            title = (try? c.decode(String.self, forKey: .title)) ?? ruleId
            grants = (try? c.decode([String].self, forKey: .grants)) ?? []
            preconditionNotes = (try? c.decode([String].self, forKey: .preconditionNotes)) ?? []
            let location = try? c.decode(Location.self, forKey: .location)
            file = location?.file
            line = location?.line
        }

        /// `app.py:12`, or the file alone.
        var place: String? {
            guard let file else { return nil }
            return line.map { "\(file):\($0)" } ?? file
        }
    }

    enum CodingKeys: String, CodingKey { case id, impact, likelihood, start, steps }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        impact = (try? c.decode(String.self, forKey: .impact)) ?? ""
        likelihood = (try? c.decode(Double.self, forKey: .likelihood)) ?? 0
        start = (try? c.decode([String].self, forKey: .start)) ?? []
        steps = (try? c.decode([Step].self, forKey: .steps)) ?? []
    }

    /// `secrets` → "Secrets"; capability ids are snake_case.
    static func label(_ capability: String) -> String {
        capability.replacingOccurrences(of: "_", with: " ").capitalized
    }
}
