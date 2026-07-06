import Foundation

/// User-chosen options for a scan, and the translation into `attackmap` CLI
/// arguments. Kept free of UI types so it stays unit-testable.
struct ScanConfig: Equatable {
    var repoURL: URL
    var outputDirectory: URL
    var runCVE: Bool = false
    var llmMode: LLMMode = .none
    var baselineURL: URL?

    enum LLMMode: String, CaseIterable, Identifiable, Equatable {
        case none, review, hunt, huntVerify, remediate
        var id: String { rawValue }
        var label: String {
            switch self {
            case .none: return "None (heuristic only)"
            case .review: return "Review (--llm)"
            case .hunt: return "Hunt hypotheses (--hunt)"
            case .huntVerify: return "Hunt + verify (--hunt --verify)"
            case .remediate: return "Remediate (--remediate)"
            }
        }
    }

    /// The `attackmap analyze …` argument vector for this configuration.
    func arguments() -> [String] {
        var args = [
            "analyze", repoURL.path,
            "--format", "json",
            "--output", outputDirectory.path,
            "--progress-format", "json",
        ]
        if runCVE { args += ["--cve"] }
        switch llmMode {
        case .none: break
        case .review: args += ["--llm"]
        case .hunt: args += ["--hunt"]
        case .huntVerify: args += ["--hunt", "--verify"]
        case .remediate: args += ["--remediate"]
        }
        if let baselineURL { args += ["--baseline", baselineURL.path] }
        return args
    }

    /// Where the monolithic report lands after a run.
    var reportURL: URL {
        outputDirectory.appendingPathComponent("attackmap-report.json")
    }
}
