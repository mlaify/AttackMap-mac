import Foundation

/// User-chosen options for a scan, and the translation into `attackmap` CLI
/// arguments. Kept free of UI types so it stays unit-testable.
struct ScanConfig: Equatable {
    var repoURL: URL
    var outputDirectory: URL
    var runCVE: Bool = false
    var llmMode: LLMMode = .none
    var model: LLMModel = .opus48
    var effort: Effort = .high
    var fast: Bool = false
    var baselineURL: URL?

    /// Claude models the engine accepts for `--llm-model` (verified IDs).
    enum LLMModel: String, CaseIterable, Identifiable, Equatable {
        case opus48 = "claude-opus-4-8"
        case fable5 = "claude-fable-5"
        case sonnet5 = "claude-sonnet-5"
        case opus47 = "claude-opus-4-7"
        case opus46 = "claude-opus-4-6"
        case sonnet46 = "claude-sonnet-4-6"
        var id: String { rawValue }
        var label: String {
            switch self {
            case .opus48: return "Opus 4.8"
            case .fable5: return "Fable 5"
            case .sonnet5: return "Sonnet 5"
            case .opus47: return "Opus 4.7"
            case .opus46: return "Opus 4.6"
            case .sonnet46: return "Sonnet 4.6"
            }
        }
        /// Fast mode is Opus 4.8 / 4.7 only.
        var fastCapable: Bool { self == .opus48 || self == .opus47 }
    }

    /// Reasoning level (`--llm-effort`).
    enum Effort: String, CaseIterable, Identifiable, Equatable {
        case low, medium, high, xhigh, max
        var id: String { rawValue }
        var label: String { self == .xhigh ? "X-High" : rawValue.capitalized }
    }

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

        /// The markdown artifact this mode is expected to produce, if any.
        var artifactFilename: String? {
            switch self {
            case .none: return nil
            case .review: return "defensive-review-llm.md"
            case .hunt, .huntVerify: return "vulnerability-hypotheses.md"
            case .remediate: return "remediation.md"
            }
        }
    }

    /// The `attackmap analyze …` argument vector for this configuration.
    ///
    /// - Parameter progressJSON: emit `--progress-format json` (NDJSON progress,
    ///   requires attackmap ≥ the M0 release). When false, fall back to
    ///   `--no-progress` so older CLIs don't fail on an unknown option.
    func arguments(progressJSON: Bool) -> [String] {
        var args = [
            "analyze", repoURL.path,
            "--format", "json",
            "--output", outputDirectory.path,
        ]
        args += progressJSON ? ["--progress-format", "json"] : ["--no-progress"]
        if runCVE { args += ["--cve"] }
        switch llmMode {
        case .none: break
        case .review: args += ["--llm"]
        case .hunt: args += ["--hunt"]
        case .huntVerify: args += ["--hunt", "--verify"]
        case .remediate: args += ["--remediate"]
        }
        // Model / reasoning / speed apply only when an LLM mode runs.
        if llmMode != .none {
            args += ["--llm-model", model.rawValue, "--llm-effort", effort.rawValue]
            if fast && model.fastCapable {
                args += ["--llm-speed", "fast"]
            }
        }
        if let baselineURL { args += ["--baseline", baselineURL.path] }
        return args
    }

    /// Where the monolithic report lands after a run.
    var reportURL: URL {
        outputDirectory.appendingPathComponent("attackmap-report.json")
    }
}
