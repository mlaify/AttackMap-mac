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
    /// Findings the engine silenced (via `.attackmap-suppress.yaml` or inline
    /// `attackmap:ignore` directives) — retained with their reason for audit (#144).
    var suppressedFindings: [SuppressedFinding]
    var attackPaths: [AttackPath]
    var attackSurfaces: [AttackSurface]
    var exploitability: [ExploitabilityScore]
    var defensiveReviewMarkdown: String?
    var architectureSummary: String?
    var attackSurfaceSummary: String?
    /// Analyzers the engine selected to run for this scan (after detect-
    /// filtering), from `review_context_pack.analyzer_metadata_used`. Empty
    /// when the CLI predates the context pack or wrote `--format markdown`.
    var analyzersRun: [AnalyzerRun]

    enum CodingKeys: String, CodingKey {
        case scan, findings, exploitability
        case reviewContextPack = "review_context_pack"
        case suppressedFindings = "suppressed_findings"
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
        suppressedFindings = (try? c.decode([SuppressedFinding].self, forKey: .suppressedFindings)) ?? []
        attackPaths = (try? c.decode([AttackPath].self, forKey: .attackPaths)) ?? []
        attackSurfaces = (try? c.decode([AttackSurface].self, forKey: .attackSurfaces)) ?? []
        exploitability = (try? c.decode([ExploitabilityScore].self, forKey: .exploitability)) ?? []
        defensiveReviewMarkdown = try? c.decode(String.self, forKey: .defensiveReviewMarkdown)
        architectureSummary = try? c.decode(String.self, forKey: .architectureSummary)
        attackSurfaceSummary = try? c.decode(String.self, forKey: .attackSurfaceSummary)
        analyzersRun = (try? c.decode(ContextPack.self, forKey: .reviewContextPack))?.analyzers ?? []
    }

    /// Just the slice of `review_context_pack` the GUI reads.
    private struct ContextPack: Decodable {
        let analyzers: [AnalyzerRun]
        enum CodingKeys: String, CodingKey { case analyzers = "analyzer_metadata_used" }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            analyzers = (try? c.decode([AnalyzerRun].self, forKey: .analyzers)) ?? []
        }
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
    /// Stable detector id (`attackmap rules`; also the SARIF ruleId). `nil`
    /// on CLIs that predate stable rule ids — the suppress sheet then falls
    /// back to the title slug, which core still accepts (deprecated).
    let ruleId: String?
    /// Structured per-instance locations (core #214); empty on older CLIs.
    let locations: [FindingLocation]

    var severityRank: Int { Severity(severity).rank }

    /// The rule id a `rule:` suppression must name: the stable id, else the
    /// legacy title slug (core's `finding_rule_id`).
    var effectiveRuleId: String { ruleId ?? Finding.titleSlug(title) }

    /// Core's `title_slug`: lowercase, runs of non-`[a-z0-9]` → `-`, trimmed.
    static func titleSlug(_ title: String) -> String {
        var out = ""
        var pendingDash = false
        for scalar in title.lowercased().unicodeScalars {
            if ("a"..."z").contains(scalar) || ("0"..."9").contains(scalar) {
                if pendingDash && !out.isEmpty { out.append("-") }
                pendingDash = false
                out.unicodeScalars.append(scalar)
            } else {
                pendingDash = true
            }
        }
        return out.isEmpty ? "finding" : out
    }

    /// Distinct files this finding cites, from structured locations.
    var locationFiles: [String] {
        var seen: [String] = []
        for loc in locations where !loc.file.isEmpty && !seen.contains(loc.file) { seen.append(loc.file) }
        return seen
    }

    enum CodingKeys: String, CodingKey {
        case id, title, severity, confidence, evidence, mitigation, tags, score, exploitability, locations
        case attackTechniques = "attack_techniques"
        case exploitabilityTier = "exploitability_tier"
        case ruleId = "rule_id"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
        title = (try? c.decode(String.self, forKey: .title)) ?? "(untitled)"
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
        confidence = (try? c.decode(String.self, forKey: .confidence)) ?? "unknown"
        evidence = (try? c.decode([String].self, forKey: .evidence)) ?? []
        mitigation = try? c.decode(String.self, forKey: .mitigation)
        // The engine emits ATT&CK refs as objects ({technique_id, name, tactic, url});
        // accept plain strings too for older/hand-written reports.
        if let refs = try? c.decode([AttackTechniqueRef].self, forKey: .attackTechniques) {
            attackTechniques = refs.map(\.display)
        } else {
            attackTechniques = (try? c.decode([String].self, forKey: .attackTechniques)) ?? []
        }
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        score = try? c.decode(Int.self, forKey: .score)
        exploitability = try? c.decode(Int.self, forKey: .exploitability)
        exploitabilityTier = try? c.decode(String.self, forKey: .exploitabilityTier)
        ruleId = try? c.decode(String.self, forKey: .ruleId)
        locations = (try? c.decode([FindingLocation].self, forKey: .locations)) ?? []
    }
}

/// One instance of a finding (`Finding.locations`).
struct FindingLocation: Decodable, Hashable {
    let file: String
    let line: Int?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
    }

    enum CodingKeys: String, CodingKey { case file, line }
}

/// One MITRE ATT&CK reference as the engine serializes it.
struct AttackTechniqueRef: Decodable, Hashable {
    let techniqueId: String
    let name: String?
    let tactic: String?

    enum CodingKeys: String, CodingKey {
        case name, tactic
        case techniqueId = "technique_id"
    }

    var display: String {
        [techniqueId, name, tactic.map { "(\($0))" }].compactMap { $0 }.joined(separator: " ")
    }
}

/// A finding the engine matched against a suppression selector and silenced.
/// Carries the full finding fields plus the rule/reason it was silenced under.
struct SuppressedFinding: Decodable, Identifiable, Hashable {
    let id: String
    let title: String
    let severity: String
    let rule: String?
    let reason: String?
    let suppressedBy: [String]

    var severityRank: Int { Severity(severity).rank }

    enum CodingKeys: String, CodingKey {
        case id, title, severity, rule, reason
        case suppressedBy = "suppressed_by"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
        title = (try? c.decode(String.self, forKey: .title)) ?? "(untitled)"
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
        rule = try? c.decode(String.self, forKey: .rule)
        reason = try? c.decode(String.self, forKey: .reason)
        suppressedBy = (try? c.decode([String].self, forKey: .suppressedBy)) ?? []
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

/// Recon-level summary plus the inventory sections the GUI shows
/// (dependencies, CVEs, secrets, CI workflow issues, data flows, analyzer
/// errors). Every field is decoded independently and defaults to empty, so an
/// older CLI that omits a section (or a newer one that reshapes it) degrades
/// to "nothing to show" instead of failing the whole report.
struct Scan: Decodable {
    let root: String
    let languages: [String]
    let routes: [Route]
    let filesScanned: Int
    let dependencies: [Dependency]
    let vulnerabilities: [Vulnerability]
    let secrets: [SecretHint]
    let workflowIssues: [WorkflowIssue]
    let taintChains: [TaintChain]
    let analyzerErrors: [AnalyzerError]
    /// What the scan deliberately did not analyze (core #234).
    let limitations: [String]

    enum CodingKeys: String, CodingKey {
        case root, languages, routes, dependencies, vulnerabilities, limitations
        case filesScanned = "files_scanned"
        case secrets = "secret_hints"
        case workflowIssues = "workflow_issues"
        case taintChains = "taint_chains"
        case analyzerErrors = "analyzer_errors"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        root = (try? c.decode(String.self, forKey: .root)) ?? ""
        languages = (try? c.decode([String].self, forKey: .languages)) ?? []
        routes = (try? c.decode([Route].self, forKey: .routes)) ?? []
        filesScanned = (try? c.decode(Int.self, forKey: .filesScanned)) ?? 0
        dependencies = (try? c.decode([Dependency].self, forKey: .dependencies)) ?? []
        vulnerabilities = (try? c.decode([Vulnerability].self, forKey: .vulnerabilities)) ?? []
        secrets = (try? c.decode([SecretHint].self, forKey: .secrets)) ?? []
        workflowIssues = (try? c.decode([WorkflowIssue].self, forKey: .workflowIssues)) ?? []
        taintChains = (try? c.decode([TaintChain].self, forKey: .taintChains)) ?? []
        analyzerErrors = (try? c.decode([AnalyzerError].self, forKey: .analyzerErrors)) ?? []
        limitations = (try? c.decode([String].self, forKey: .limitations)) ?? []
    }
}

struct Route: Decodable, Identifiable, Hashable {
    var id: String { "\(method) \(path) \(file):\(line ?? 0)" }
    let path: String
    let method: String
    let file: String
    let line: Int?
    /// Route-level auth as the analyzer resolved it (core #256):
    /// `required` / `anonymous` / `unknown`.
    let auth: String
    let guards: [String]
    /// Analyzer that emitted the route. Core currently excludes provenance
    /// from serialization, so this is usually nil; shown when present.
    let sourceAnalyzer: String?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = (try? c.decode(String.self, forKey: .path)) ?? ""
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
        auth = (try? c.decode(String.self, forKey: .auth)) ?? "unknown"
        guards = (try? c.decode([String].self, forKey: .guards)) ?? []
        sourceAnalyzer = try? c.decode(String.self, forKey: .sourceAnalyzer)
    }

    enum CodingKeys: String, CodingKey {
        case path, method, file, line, auth, guards
        case sourceAnalyzer = "source_analyzer"
    }
}
