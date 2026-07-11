import Foundation

/// One installed analyzer module, as reported by `attackmap modules --json`
/// (available on attackmap ≥ 0.4.4). Drives the GUI's Analyzers picker; the
/// `name` is what gets passed back as `--module <name>`.
struct AnalyzerModule: Decodable, Identifiable, Equatable {
    let name: String
    let displayName: String
    let description: String
    let scope: String
    let ecosystems: [String]
    let enabledByDefault: Bool

    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name
        case displayName = "display_name"
        case description
        case scope
        case ecosystems
        case enabledByDefault = "enabled_by_default"
    }
}
