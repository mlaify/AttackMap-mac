import Foundation

// Inventory sections of `attackmap-report.json` → `scan` (core models.py).
// Every field decodes with `try?` and a default so older CLIs that omit a key
// — or newer ones that add a Literal case the app doesn't know — never sink
// the report. String-typed enums (`kind`, `severity`, `ecosystem`) are kept as
// raw strings for the same reason.

/// A third-party dependency from a manifest or lockfile (`DependencyHint`).
struct Dependency: Decodable, Identifiable, Hashable {
    var id: String { "\(ecosystem) \(name) \(version) \(file):\(line ?? 0) \(via ?? "")" }
    let name: String
    let version: String
    let ecosystem: String
    let file: String
    let line: Int?
    let dev: Bool
    /// Exact pinned version from a lockfile (vs. a manifest range).
    let resolved: Bool
    /// False for a transitive dependency; `via` is its resolution path.
    let direct: Bool
    let via: String?
    let sourceAnalyzer: String?

    enum CodingKeys: String, CodingKey {
        case name, version, ecosystem, file, line, dev, resolved, direct, via
        case sourceAnalyzer = "source_analyzer"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = (try? c.decode(String.self, forKey: .name)) ?? "(unnamed)"
        version = (try? c.decode(String.self, forKey: .version)) ?? ""
        ecosystem = (try? c.decode(String.self, forKey: .ecosystem)) ?? "unknown"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
        dev = (try? c.decode(Bool.self, forKey: .dev)) ?? false
        resolved = (try? c.decode(Bool.self, forKey: .resolved)) ?? false
        direct = (try? c.decode(Bool.self, forKey: .direct)) ?? true
        via = try? c.decode(String.self, forKey: .via)
        sourceAnalyzer = try? c.decode(String.self, forKey: .sourceAnalyzer)
    }
}

/// A known advisory affecting a dependency (`Vulnerability`; `--cve` scans).
struct Vulnerability: Decodable, Identifiable, Hashable {
    var id: String { "\(advisoryId) \(ecosystem) \(packageName) \(packageVersion)" }
    /// OSV id — CVE-…, GHSA-…, etc.
    let advisoryId: String
    let aliases: [String]
    let summary: String
    let severity: String
    let cvssScore: Double?
    let references: [String]
    let affectedRange: String
    let packageName: String
    let packageVersion: String
    let ecosystem: String
    let direct: Bool
    let resolutionPath: String

    var severityRank: Int { Severity(severity).rank }

    /// First CVE alias when the primary id is a GHSA/OSV id — what most people
    /// search for.
    var cveAlias: String? {
        if advisoryId.hasPrefix("CVE-") { return nil }
        return aliases.first { $0.hasPrefix("CVE-") }
    }

    enum CodingKeys: String, CodingKey {
        case aliases, summary, severity, references, ecosystem, direct
        case advisoryId = "id"
        case cvssScore = "cvss_score"
        case affectedRange = "affected_range"
        case packageName = "package_name"
        case packageVersion = "package_version"
        case resolutionPath = "resolution_path"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        advisoryId = (try? c.decode(String.self, forKey: .advisoryId)) ?? "(unknown advisory)"
        aliases = (try? c.decode([String].self, forKey: .aliases)) ?? []
        summary = (try? c.decode(String.self, forKey: .summary)) ?? ""
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "medium"
        cvssScore = try? c.decode(Double.self, forKey: .cvssScore)
        references = (try? c.decode([String].self, forKey: .references)) ?? []
        affectedRange = (try? c.decode(String.self, forKey: .affectedRange)) ?? ""
        packageName = (try? c.decode(String.self, forKey: .packageName)) ?? ""
        packageVersion = (try? c.decode(String.self, forKey: .packageVersion)) ?? ""
        ecosystem = (try? c.decode(String.self, forKey: .ecosystem)) ?? "unknown"
        direct = (try? c.decode(Bool.self, forKey: .direct)) ?? true
        resolutionPath = (try? c.decode(String.self, forKey: .resolutionPath)) ?? ""
    }
}

/// A secret reference or hard-coded literal (`SecretHint`).
///
/// Deliberately models **only** name / kind / location / confidence. The
/// engine's `evidence_text` is redacted at source, but the GUI never decodes
/// it at all — a secrets pane has no business rendering source lines.
struct SecretHint: Decodable, Identifiable, Hashable {
    var id: String { "\(file):\(line ?? 0) \(name) \(kind)" }
    /// The variable / key name (for literals, core's redacted prefix).
    let name: String
    let file: String
    let line: Int?
    /// `env_reference` (read from the environment at runtime) or a detector
    /// classification for a literal pasted into code/config.
    let kind: String
    let confidence: Double?
    let sourceAnalyzer: String?

    var isLiteral: Bool { kind != "env_reference" }

    enum CodingKeys: String, CodingKey {
        case name, file, line, kind, confidence
        case sourceAnalyzer = "source_analyzer"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = (try? c.decode(String.self, forKey: .name)) ?? "(unnamed)"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? "env_reference"
        confidence = try? c.decode(Double.self, forKey: .confidence)
        sourceAnalyzer = try? c.decode(String.self, forKey: .sourceAnalyzer)
    }
}

/// A GitHub Actions misconfiguration (`WorkflowIssue`).
struct WorkflowIssue: Decodable, Identifiable, Hashable {
    var id: String { "\(file):\(line ?? 0) \(kind) \(context ?? "")" }
    let kind: String
    let file: String
    let line: Int?
    let context: String?
    let evidence: String?
    let severity: String

    var severityRank: Int { Severity(severity).rank }
    /// `unpinned_action` → "Unpinned action".
    var kindLabel: String { Self.humanize(kind) }

    static func humanize(_ raw: String) -> String {
        let spaced = raw.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    enum CodingKeys: String, CodingKey {
        case kind, file, line, context, severity
        case evidence = "evidence_text"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? "unknown"
        file = (try? c.decode(String.self, forKey: .file)) ?? ""
        line = try? c.decode(Int.self, forKey: .line)
        context = try? c.decode(String.self, forKey: .context)
        evidence = try? c.decode(String.self, forKey: .evidence)
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "medium"
    }
}

/// Route → sink data-flow evidence (`TaintChain`).
struct TaintChain: Decodable, Identifiable, Hashable {
    var id: String { "\(routeMethod) \(routePath) → \(sinkKind) \(sinkFile):\(sinkLine ?? 0)" }
    let routePath: String
    let routeMethod: String
    let routeFile: String
    let sinkKind: String
    let sinkFile: String
    let sinkLine: Int?
    let hops: Int
    let confidence: Double?
    let sanitized: Bool
    let speculative: Bool

    enum CodingKeys: String, CodingKey {
        case hops, confidence, sanitized, speculative
        case routePath = "route_path"
        case routeMethod = "route_method"
        case routeFile = "route_file"
        case sinkKind = "sink_kind"
        case sinkFile = "sink_file"
        case sinkLine = "sink_line"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        routePath = (try? c.decode(String.self, forKey: .routePath)) ?? ""
        routeMethod = (try? c.decode(String.self, forKey: .routeMethod)) ?? "ANY"
        routeFile = (try? c.decode(String.self, forKey: .routeFile)) ?? ""
        sinkKind = (try? c.decode(String.self, forKey: .sinkKind)) ?? "unknown"
        sinkFile = (try? c.decode(String.self, forKey: .sinkFile)) ?? ""
        sinkLine = try? c.decode(Int.self, forKey: .sinkLine)
        hops = (try? c.decode(Int.self, forKey: .hops)) ?? 0
        confidence = try? c.decode(Double.self, forKey: .confidence)
        sanitized = (try? c.decode(Bool.self, forKey: .sanitized)) ?? false
        speculative = (try? c.decode(Bool.self, forKey: .speculative)) ?? false
    }
}

/// An analyzer that failed and was skipped (`AnalyzerError`, core #220).
struct AnalyzerError: Decodable, Identifiable, Hashable {
    var id: String { "\(analyzer) \(errorType) \(message)" }
    let analyzer: String
    let errorType: String
    let message: String

    enum CodingKeys: String, CodingKey {
        case analyzer, message
        case errorType = "error_type"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        analyzer = (try? c.decode(String.self, forKey: .analyzer)) ?? "(unknown analyzer)"
        errorType = (try? c.decode(String.self, forKey: .errorType)) ?? "Error"
        message = (try? c.decode(String.self, forKey: .message)) ?? ""
    }
}

/// An analyzer the engine ran (`review_context_pack.analyzer_metadata_used`).
struct AnalyzerRun: Decodable, Identifiable, Hashable {
    var id: String { name }
    let name: String
    let description: String?
    let scope: String?
    let ecosystems: [String]

    enum CodingKeys: String, CodingKey { case name, description, scope, ecosystems }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = (try? c.decode(String.self, forKey: .name)) ?? "(unnamed)"
        description = try? c.decode(String.self, forKey: .description)
        scope = try? c.decode(String.self, forKey: .scope)
        ecosystems = (try? c.decode([String].self, forKey: .ecosystems)) ?? []
    }
}
