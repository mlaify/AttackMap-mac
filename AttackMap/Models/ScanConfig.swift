import Foundation

/// User-chosen options for a scan, and the translation into `attackmap` CLI
/// arguments. Kept free of UI types so it stays unit-testable.
struct ScanConfig: Equatable {
    var repoURL: URL
    var outputDirectory: URL
    var runCVE: Bool = false
    /// Analyzer module names to run (`--module`). Empty = automatic: let the
    /// engine pick the analyzers relevant to the repo (its default behavior).
    var modules: [String] = []
    var llmMode: LLMMode = .none
    var provider: Provider = .claude
    /// Claude model ID for `--llm-model`; any ID the account can use, gated ones included.
    var model: String = "claude-opus-5-5"
    /// OpenAI model ID; empty lets the engine use the account's Codex default.
    var openAIModel: String = ""
    /// Codex cyber access program (`--llm-access-program`, ≥ 1.1), e.g. daybreak_blue;
    /// empty uses the account's own default (the Daybreak setting in ChatGPT).
    var accessProgram: String = ""
    var effort: Effort = .high
    var fast: Bool = false
    /// Whether the chosen Claude model has fast mode (from `llm-models`, else by ID).
    var fastCapable: Bool = false
    /// Recall mode (`--recall`, ≥ 0.4.20): widen taint discovery. The extra
    /// reach is marked SPECULATIVE by the engine and kept out of the high-severity
    /// gate; pair with Hunt + verify to adjudicate it.
    var recall: Bool = false
    /// Ignore all suppressions (`--no-suppress`, ≥ 0.4.7) for a full audit.
    var noSuppress: Bool = false
    /// Explicit suppression baseline (`--suppress-file`), overriding the repo's
    /// auto-discovered `.attackmap-suppress.yaml`.
    var suppressFileURL: URL?
    /// Hunt verify-jury knobs (≥ 0.4.16), emitted only for Hunt + verify.
    var jury: Jury = Jury()
    /// Prior `attackmap-report.json` to diff against (`--baseline`).
    var baselineURL: URL?
    /// Where to write the Markdown diff (`--diff-output`); only emitted with a
    /// baseline. `nil` lets the engine default to `<output>/attackmap-diff.md`.
    var diffOutputURL: URL?
    /// Exit non-zero when the diff introduces new HIGH findings
    /// (`--fail-on-new-high`); only emitted with a baseline.
    var failOnNewHigh: Bool = false
    /// Write a Markdown PR summary comment here (`--pr-comment`).
    var prCommentURL: URL?
    /// Hide findings below this confidence (`--min-confidence`, ≥ 0.8). `.low`
    /// shows everything and emits no flag.
    var minConfidence: MinConfidence = .low
    /// Local model (`--llm-provider local`, ≥ 0.8): its name and, optionally,
    /// the OpenAI-compatible server URL (the engine defaults to Ollama).
    var localModel: String = ""
    var localBaseURL: String = ""

    enum MinConfidence: String, CaseIterable, Identifiable, Equatable {
        case low, medium, high
        var id: String { rawValue }
        var label: String {
            switch self {
            case .low: return "All findings"
            case .medium: return "Medium confidence and up"
            case .high: return "High confidence only"
            }
        }
    }

    /// Multi-pass hunt-verify tuning (`--verify-votes` / `--hunt-lenses` /
    /// `--hunt-rounds` / `--hunt-budget`). Defaults match the engine's, so an
    /// untouched jury emits no extra flags.
    struct Jury: Equatable {
        var verifyVotes: Int = 3      // skeptic passes; majority to CONFIRM
        var lenses: Int = 1           // failure-mode generation passes
        var rounds: Int = 1           // loop-until-dry generation rounds
        var budget: Int = 0           // output-token cap across rounds (0 = none)
    }

    /// LLM provider (`--llm-provider`). Claude is the default and needs no flag;
    /// OpenAI emits `--llm-provider openai` (requires attackmap ≥ 0.4.3).
    enum Provider: String, CaseIterable, Identifiable, Equatable {
        case claude, openai, local
        var id: String { rawValue }
        var label: String {
            switch self {
            case .claude: return "Claude"
            case .openai: return "OpenAI / Codex"
            case .local: return "Local model"
            }
        }
    }

    /// Reasoning level (`--llm-effort`).
    enum Effort: String, CaseIterable, Identifiable, Equatable {
        case low, medium, high, xhigh, max
        var id: String { rawValue }
        var label: String { self == .xhigh ? "X-High" : rawValue.capitalized }
    }

    enum LLMMode: String, CaseIterable, Identifiable, Equatable {
        case none, review, hunt, huntVerify, remediate, triage
        var id: String { rawValue }
        var label: String {
            switch self {
            case .none: return "None (heuristic only)"
            case .review: return "Review (--llm)"
            case .hunt: return "Hunt hypotheses (--hunt)"
            case .huntVerify: return "Hunt + verify (--hunt --verify)"
            case .remediate: return "Remediate (--remediate)"
            case .triage: return "Triage findings (--triage)"
            }
        }

        /// The markdown artifact this mode is expected to produce, if any.
        var artifactFilename: String? {
            switch self {
            case .none: return nil
            case .review: return "defensive-review-llm.md"
            case .hunt, .huntVerify: return "vulnerability-hypotheses.md"
            case .remediate: return "remediation.md"
            case .triage: return "triage.md"
            }
        }
    }

    /// The `attackmap analyze …` argument vector for this configuration.
    ///
    /// - Parameter progressJSON: emit `--progress-format json` (NDJSON progress,
    ///   requires attackmap ≥ the M0 release). When false, fall back to
    ///   `--no-progress` so older CLIs don't fail on an unknown option.
    func arguments(progressJSON: Bool) -> [String] {
        // `--format all`: the app reads both the JSON report and the Markdown
        // diagram files (attackmap-paths.md / attackmap-topology.md). From
        // attackmap 0.4.30 `--format json` really does skip the Markdown set.
        var args = [
            "analyze", repoURL.path,
            "--format", "all",
            "--output", outputDirectory.path,
        ]
        args += progressJSON ? ["--progress-format", "json"] : ["--no-progress"]
        if runCVE { args += ["--cve"] }
        if recall { args += ["--recall"] }
        if noSuppress { args += ["--no-suppress"] }
        if let suppressFileURL { args += ["--suppress-file", suppressFileURL.path] }
        // Empty = automatic (engine auto-resolves analyzers by repo language).
        for module in modules.sorted() { args += ["--module", module] }
        switch llmMode {
        case .none: break
        case .review: args += ["--llm"]
        case .hunt: args += ["--hunt"]
        case .huntVerify: args += ["--hunt", "--verify"]
        case .remediate: args += ["--remediate"]
        case .triage: args += ["--triage"]
        }
        // Verify-jury tuning applies only to Hunt + verify; emit each knob only
        // when it differs from the engine default so older CLIs stay happy when
        // the user leaves them alone.
        if llmMode == .huntVerify {
            if jury.verifyVotes != 3 { args += ["--verify-votes", String(jury.verifyVotes)] }
            if jury.lenses != 1 { args += ["--hunt-lenses", String(jury.lenses)] }
            if jury.rounds != 1 { args += ["--hunt-rounds", String(jury.rounds)] }
            if jury.budget > 0 { args += ["--hunt-budget", String(jury.budget)] }
        }
        // Provider / model / reasoning / speed apply only when an LLM mode runs.
        if llmMode != .none {
            switch provider {
            case .claude:
                // Claude is the engine default; omit --llm-provider so older
                // CLIs that predate the flag still work.
                let claudeModel = model.trimmingCharacters(in: .whitespaces)
                if !claudeModel.isEmpty { args += ["--llm-model", claudeModel] }
                args += ["--llm-effort", effort.rawValue]
                if fast && fastCapable {
                    args += ["--llm-speed", "fast"]
                }
            case .openai:
                args += ["--llm-provider", "openai"]
                let openAI = openAIModel.trimmingCharacters(in: .whitespaces)
                if !openAI.isEmpty { args += ["--llm-model", openAI] }
                args += ["--llm-effort", effort.rawValue]
                if !accessProgram.isEmpty { args += ["--llm-access-program", accessProgram] }
                // Fast mode is Claude-only; never emit it for OpenAI.
            case .local:
                // An OpenAI-compatible server on this machine or network (≥ 0.8).
                args += ["--llm-provider", "local", "--llm-model", localModel]
                let url = localBaseURL.trimmingCharacters(in: .whitespaces)
                if !url.isEmpty { args += ["--llm-base-url", url] }
            }
        }
        if let baselineURL {
            args += ["--baseline", baselineURL.path]
            // Both require --baseline; the engine rejects them without it.
            if let diffOutputURL { args += ["--diff-output", diffOutputURL.path] }
            if failOnNewHigh { args += ["--fail-on-new-high"] }
        }
        if let prCommentURL { args += ["--pr-comment", prCommentURL.path] }
        if minConfidence != .low { args += ["--min-confidence", minConfidence.rawValue] }
        return args
    }

    /// The `attackmap analyze <repoA> <repoB> …` argument vector for a cross-repo
    /// fleet scan (≥ 0.4.22). Only the fleet-compatible options are emitted; the
    /// engine rejects single-repo-only flags (LLM modes, baseline/diff) in multi
    /// mode, so they're deliberately omitted here.
    func fleetArguments(paths: [URL], progressJSON: Bool) -> [String] {
        var args = ["analyze"]
        args += paths.map(\.path)
        // `all`, not `json`: the Fleet view renders fleet-graph.md (Markdown).
        args += ["--format", "all", "--output", outputDirectory.path]
        args += progressJSON ? ["--progress-format", "json"] : ["--no-progress"]
        if runCVE { args += ["--cve"] }
        if recall { args += ["--recall"] }
        if noSuppress { args += ["--no-suppress"] }
        if let suppressFileURL { args += ["--suppress-file", suppressFileURL.path] }
        for module in modules.sorted() { args += ["--module", module] }
        if minConfidence != .low { args += ["--min-confidence", minConfidence.rawValue] }
        return args
    }

    /// Where the monolithic report lands after a run.
    var reportURL: URL {
        outputDirectory.appendingPathComponent("attackmap-report.json")
    }

    /// Where the baseline diff lands (explicit `--diff-output`, else the
    /// engine's default next to the report).
    var diffURL: URL {
        diffOutputURL ?? outputDirectory.appendingPathComponent("attackmap-diff.md")
    }

    /// The SARIF 2.1.0 report the engine writes alongside the JSON.
    var sarifURL: URL {
        outputDirectory.appendingPathComponent("attackmap-report.sarif")
    }

    /// The fleet summary JSON location (multi-repo mode).
    var fleetSummaryURL: URL {
        outputDirectory.appendingPathComponent("fleet-summary.json")
    }
}
