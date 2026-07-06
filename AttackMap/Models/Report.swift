import Foundation

/// Decoded view of `attackmap-report.json` (the engine's monolithic artifact).
///
/// Decoding is deliberately tolerant: each top-level collection is decoded
/// independently so a schema drift in one section (the engine evolves faster
/// than this app) can't sink the whole report. Missing/renamed fields degrade
/// to empty/`nil` rather than throwing.
struct Report: Decodable {
    var scan: Scan?
    var findings: [Finding]
    var attackPaths: [AttackPath]
    var attackSurfaces: [AttackSurface]
    var exploitability: [ExploitabilityScore]
    var defensiveReviewMarkdown: String?
    var architectureSummary: String?
    var attackSurfaceSummary: String?

    enum CodingKeys: String, CodingKey {
        case scan, findings, exploitability
        case attackPaths = "attack_paths"
        case attackSurfaces = "attack_surfaces"
        case defensiveReviewMarkdown = "defensive_review"
        case architectureSummary = "architecture_summary"
        case attackSurfaceSummary = "attack_surface_summary"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        scan = try? c.decode(Scan.self, forKey: .scan)
        findings = (try? c.decode([Finding].self, forKey: .findings)) ?? []
        attackPaths = (try? c.decode([AttackPath].self, forKey: .attackPaths)) ?? []
        attackSurfaces = (try? c.decode([AttackSurface].self, forKey: .attackSurfaces)) ?? []
        exploitability = (try? c.decode([ExploitabilityScore].self, forKey: .exploitability)) ?? []
        defensiveReviewMarkdown = try? c.decode(String.self, forKey: .defensiveReviewMarkdown)
        architectureSummary = try? c.decode(String.self, forKey: .architectureSummary)
        attackSurfaceSummary = try? c.decode(String.self, forKey: .attackSurfaceSummary)
    }

    /// Load and decode a report from disk.
    static func load(from url: URL) throws -> Report {
        try JSONDecoder().decode(Report.self, from: try Data(contentsOf: url))
    }

    /// Findings ordered most-severe first, then by exploitability/score.
    var findingsByPriority: [Finding] {
        findings.sorted {
            if $0.severityRank != $1.severityRank { return $0.severityRank > $1.severityRank }
            return ($0.exploitability ?? $0.score ?? 0) > ($1.exploitability ?? $1.score ?? 0)
        }
    }
}

/// Ordered severity for sorting/coloring; unknown sorts last.
enum Severity: String {
    case critical, high, medium, low, info, unknown

    init(_ raw: String) { self = Severity(rawValue: raw.lowercased()) ?? .unknown }

    var rank: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        case .unknown: return 0
        }
    }
}

struct Finding: Decodable, Identifiable, Hashable {
    let id: String
    let title: String
    let severity: String
    let confidence: String
    let evidence: [String]
    let mitigation: String?
    let attackTechniques: [String]
    let tags: [String]
    let score: Int?
    let exploitability: Int?
    let exploitabilityTier: String?

    var severityRank: Int { Severity(severity).rank }

    enum CodingKeys: String, CodingKey {
        case id, title, severity, confidence, evidence, mitigation, tags, score, exploitability
        case attackTechniques = "attack_techniques"
        case exploitabilityTier = "exploitability_tier"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
        title = (try? c.decode(String.self, forKey: .title)) ?? "(untitled)"
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
        confidence = (try? c.decode(String.self, forKey: .confidence)) ?? "unknown"
        evidence = (try? c.decode([String].self, forKey: .evidence)) ?? []
        mitigation = try? c.decode(String.self, forKey: .mitigation)
        attackTechniques = (try? c.decode([String].self, forKey: .attackTechniques)) ?? []
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        score = try? c.decode(Int.self, forKey: .score)
        exploitability = try? c.decode(Int.self, forKey: .exploitability)
        exploitabilityTier = try? c.decode(String.self, forKey: .exploitabilityTier)
    }
}

struct AttackPath: Decodable, Identifiable, Hashable {
    var id: String { name }
    let name: String
    let steps: [String]
    let impact: String

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = (try? c.decode(String.self, forKey: .name)) ?? "(unnamed path)"
        steps = (try? c.decode([String].self, forKey: .steps)) ?? []
        impact = (try? c.decode(String.self, forKey: .impact)) ?? ""
    }

    enum CodingKeys: String, CodingKey { case name, steps, impact }
}

struct AttackSurface: Decodable, Identifiable, Hashable {
    var id: String { "\(method) \(route) \(file):\(line ?? 0)" }
    let route: String
    let method: String
    let file: String
    let category: String
    let exposure: String
    let risk: String
    let authSignals: [String]
    let rationale: [String]
    let line: Int?

    enum CodingKeys: String, CodingKey {
        case route, method, file, category, exposure, risk, rationale, line
        case authSignals = "auth_signals"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        route = (try? c.decode(String.self, forKey: .route)) ?? ""
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        category = (try? c.decode(String.self, forKey: .category)) ?? "unknown"
        exposure = (try? c.decode(String.self, forKey: .exposure)) ?? "unknown"
        risk = (try? c.decode(String.self, forKey: .risk)) ?? "unknown"
        authSignals = (try? c.decode([String].self, forKey: .authSignals)) ?? []
        rationale = (try? c.decode([String].self, forKey: .rationale)) ?? []
        line = try? c.decode(Int.self, forKey: .line)
    }
}

struct ExploitabilityScore: Decodable, Identifiable, Hashable {
    var id: String { "\(subject) \(location)" }
    let subject: String
    let route: String?
    let method: String?
    let sinkKind: String?
    let location: String
    let score: Int
    let rawScore: Int?
    let tier: String?
    let factors: [ExploitabilityFactor]

    enum CodingKeys: String, CodingKey {
        case subject, route, method, location, score, tier, factors
        case sinkKind = "sink_kind"
        case rawScore = "raw_score"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        subject = (try? c.decode(String.self, forKey: .subject)) ?? ""
        route = try? c.decode(String.self, forKey: .route)
        method = try? c.decode(String.self, forKey: .method)
        sinkKind = try? c.decode(String.self, forKey: .sinkKind)
        location = (try? c.decode(String.self, forKey: .location)) ?? ""
        score = (try? c.decode(Int.self, forKey: .score)) ?? 0
        rawScore = try? c.decode(Int.self, forKey: .rawScore)
        tier = try? c.decode(String.self, forKey: .tier)
        factors = (try? c.decode([ExploitabilityFactor].self, forKey: .factors)) ?? []
    }
}

/// A single scored factor behind an exploitability score. Fields are all
/// optional so an engine-side reshaping of the factor object never breaks decode.
struct ExploitabilityFactor: Decodable, Hashable {
    let name: String?
    let points: Int?
    let detail: String?
}

/// Recon-level summary. Only the fields the GUI surfaces are modeled; the many
/// other signal arrays in `scan` are ignored.
struct Scan: Decodable {
    let root: String
    let languages: [String]
    let routes: [Route]
    let filesScanned: Int

    enum CodingKeys: String, CodingKey {
        case root, languages, routes
        case filesScanned = "files_scanned"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        root = (try? c.decode(String.self, forKey: .root)) ?? ""
        languages = (try? c.decode([String].self, forKey: .languages)) ?? []
        routes = (try? c.decode([Route].self, forKey: .routes)) ?? []
        filesScanned = (try? c.decode(Int.self, forKey: .filesScanned)) ?? 0
    }
}

struct Route: Decodable, Identifiable, Hashable {
    var id: String { "\(method) \(path) \(file):\(line ?? 0)" }
    let path: String
    let method: String
    let file: String
    let line: Int?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = (try? c.decode(String.self, forKey: .path)) ?? ""
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
    }

    enum CodingKeys: String, CodingKey { case path, method, file, line }
}
