import Foundation

/// Decoded view of `fleet-summary.json` — the machine-readable index the engine
/// writes for a cross-repo (multi-repo) scan (#146). Like `Report`, decoding is
/// deliberately tolerant: each section decodes independently so schema drift in
/// one collection can't sink the whole summary.
struct FleetSummary: Decodable {
    var repoCount: Int
    var totalFindings: Int
    var repos: [FleetRepo]
    var crossRepoLinks: [CrossRepoLink]
    var crossBoundaryFlows: [CrossBoundaryFlow]
    var trustGaps: [TrustGap]
    var crossRepoAnomalies: [CrossRepoAnomaly]

    enum CodingKeys: String, CodingKey {
        case repos
        case repoCount = "repo_count"
        case totalFindings = "total_findings"
        case crossRepoLinks = "cross_repo_links"
        case crossBoundaryFlows = "cross_boundary_flows"
        case trustGaps = "trust_gaps"
        case crossRepoAnomalies = "cross_repo_anomalies"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        repoCount = (try? c.decode(Int.self, forKey: .repoCount)) ?? 0
        totalFindings = (try? c.decode(Int.self, forKey: .totalFindings)) ?? 0
        repos = (try? c.decode([FleetRepo].self, forKey: .repos)) ?? []
        crossRepoLinks = (try? c.decode([CrossRepoLink].self, forKey: .crossRepoLinks)) ?? []
        crossBoundaryFlows = (try? c.decode([CrossBoundaryFlow].self, forKey: .crossBoundaryFlows)) ?? []
        trustGaps = (try? c.decode([TrustGap].self, forKey: .trustGaps)) ?? []
        crossRepoAnomalies = (try? c.decode([CrossRepoAnomaly].self, forKey: .crossRepoAnomalies)) ?? []
    }

    /// Load and decode a fleet summary from disk.
    static func load(from url: URL) throws -> FleetSummary {
        try JSONDecoder().decode(FleetSummary.self, from: try Data(contentsOf: url))
    }

    /// Total cross-repo signals surfaced (links are informational, not findings).
    var crossRepoSignalCount: Int {
        crossBoundaryFlows.count + trustGaps.count + crossRepoAnomalies.count
    }
}

struct FleetRepo: Decodable, Identifiable, Hashable {
    var id: String { repoId }
    let repoId: String
    let root: String
    let reportDir: String
    let findings: Int
    let suppressed: Int
    let severityCounts: [String: Int]

    enum CodingKeys: String, CodingKey {
        case root, findings, suppressed
        case repoId = "repo_id"
        case reportDir = "report_dir"
        case severityCounts = "severity_counts"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        repoId = (try? c.decode(String.self, forKey: .repoId)) ?? "?"
        root = (try? c.decode(String.self, forKey: .root)) ?? ""
        reportDir = (try? c.decode(String.self, forKey: .reportDir)) ?? ""
        findings = (try? c.decode(Int.self, forKey: .findings)) ?? 0
        suppressed = (try? c.decode(Int.self, forKey: .suppressed)) ?? 0
        severityCounts = (try? c.decode([String: Int].self, forKey: .severityCounts)) ?? [:]
    }

    /// Count for a severity level (case-insensitive), 0 if absent.
    func count(_ severity: Severity) -> Int {
        severityCounts.first { Severity($0.key) == severity }?.value ?? 0
    }
}

/// A discovered client→server contract: an outbound call in one repo that lines
/// up with a served route in another (matched by normalized path + method).
struct CrossRepoLink: Decodable, Identifiable, Hashable {
    var id: String { "\(clientRepo)->\(serverRepo) \(method) \(pathTemplate) \(clientLocation)" }
    let clientRepo: String
    let serverRepo: String
    let method: String
    let pathTemplate: String
    let clientTarget: String
    let clientLocation: String
    let serverRoutePath: String
    let serverLocation: String

    enum CodingKeys: String, CodingKey {
        case method
        case clientRepo = "client_repo"
        case serverRepo = "server_repo"
        case pathTemplate = "path_template"
        case clientTarget = "client_target"
        case clientLocation = "client_location"
        case serverRoutePath = "server_route_path"
        case serverLocation = "server_location"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        clientRepo = (try? c.decode(String.self, forKey: .clientRepo)) ?? "?"
        serverRepo = (try? c.decode(String.self, forKey: .serverRepo)) ?? "?"
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        pathTemplate = (try? c.decode(String.self, forKey: .pathTemplate)) ?? ""
        clientTarget = (try? c.decode(String.self, forKey: .clientTarget)) ?? ""
        clientLocation = (try? c.decode(String.self, forKey: .clientLocation)) ?? ""
        serverRoutePath = (try? c.decode(String.self, forKey: .serverRoutePath)) ?? ""
        serverLocation = (try? c.decode(String.self, forKey: .serverLocation)) ?? ""
    }
}

/// A confused-deputy / cross-boundary flow: a linked server route reaches a
/// dangerous sink or is an unguarded object reference, driven by a caller in
/// another repo. Speculative until human-verified.
struct CrossBoundaryFlow: Decodable, Identifiable, Hashable {
    var id: String { "\(clientRepo)->\(serverRepo) \(method) \(route) \(basis)" }
    let clientRepo: String
    let serverRepo: String
    let method: String
    let route: String
    let basis: String
    let detail: String
    let severity: String
    let clientLocation: String
    let serverLocation: String

    var severityRank: Int { Severity(severity).rank }

    enum CodingKeys: String, CodingKey {
        case method, route, basis, detail, severity
        case clientRepo = "client_repo"
        case serverRepo = "server_repo"
        case clientLocation = "client_location"
        case serverLocation = "server_location"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        clientRepo = (try? c.decode(String.self, forKey: .clientRepo)) ?? "?"
        serverRepo = (try? c.decode(String.self, forKey: .serverRepo)) ?? "?"
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        route = (try? c.decode(String.self, forKey: .route)) ?? ""
        basis = (try? c.decode(String.self, forKey: .basis)) ?? ""
        detail = (try? c.decode(String.self, forKey: .detail)) ?? ""
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
        clientLocation = (try? c.decode(String.self, forKey: .clientLocation)) ?? ""
        serverLocation = (try? c.decode(String.self, forKey: .serverLocation)) ?? ""
    }
}

/// A trust-assumption gap: a state-changing cross-repo call lands on a server
/// route with no detectable auth control. Speculative until verified.
struct TrustGap: Decodable, Identifiable, Hashable {
    var id: String { "\(clientRepo)->\(serverRepo) \(method) \(route)" }
    let clientRepo: String
    let serverRepo: String
    let method: String
    let route: String
    let severity: String
    let clientLocation: String
    let serverLocation: String

    var severityRank: Int { Severity(severity).rank }

    enum CodingKeys: String, CodingKey {
        case method, route, severity
        case clientRepo = "client_repo"
        case serverRepo = "server_repo"
        case clientLocation = "client_location"
        case serverLocation = "server_location"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        clientRepo = (try? c.decode(String.self, forKey: .clientRepo)) ?? "?"
        serverRepo = (try? c.decode(String.self, forKey: .serverRepo)) ?? "?"
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        route = (try? c.decode(String.self, forKey: .route)) ?? ""
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
        clientLocation = (try? c.decode(String.self, forKey: .clientLocation)) ?? ""
        serverLocation = (try? c.decode(String.self, forKey: .serverLocation)) ?? ""
    }
}

/// A cross-repo control anomaly (#149b): among peers serving the same route
/// template, this repo omits an auth control the majority enforce.
struct CrossRepoAnomaly: Decodable, Identifiable, Hashable {
    var id: String { "\(repo) \(method) \(route)" }
    let repo: String
    let method: String
    let route: String
    let template: String
    let peers: [String]
    let severity: String

    var severityRank: Int { Severity(severity).rank }

    enum CodingKeys: String, CodingKey {
        case repo, method, route, template, peers, severity
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        repo = (try? c.decode(String.self, forKey: .repo)) ?? "?"
        method = (try? c.decode(String.self, forKey: .method)) ?? "ANY"
        route = (try? c.decode(String.self, forKey: .route)) ?? ""
        template = (try? c.decode(String.self, forKey: .template)) ?? ""
        peers = (try? c.decode([String].self, forKey: .peers)) ?? []
        severity = (try? c.decode(String.self, forKey: .severity)) ?? "unknown"
    }
}
