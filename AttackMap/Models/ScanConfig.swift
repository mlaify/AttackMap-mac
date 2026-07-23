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
    var model: LLMModel = .opus48
    var openAIModel: OpenAIModel = .codex
    var effort: Effort = .high
    var fast: Bool = false
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
    var baselineURL: URL?

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
        case claude, openai
        var id: String { rawValue }
        var label: String { self == .openai ? "OpenAI / Codex" : "Claude" }
    }

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

    /// OpenAI/Codex model presets for `--llm-model`. `gpt-5-codex` is the safe
    /// default (code-optimized, Responses API); the point releases are presets
    /// for convenience — the engine passes any `--llm-model` string through.
    enum OpenAIModel: String, CaseIterable, Identifiable, Equatable {
        case codex = "gpt-5-codex"
        case gpt55 = "gpt-5.5"
        case gpt54 = "gpt-5.4"
        case gpt54mini = "gpt-5.4-mini"
        var id: String { rawValue }
        var label: String {
            switch self {
            case .codex: return "GPT-5-Codex"
            case .gpt55: return "GPT-5.5"
            case .gpt54: return "GPT-5.4"
            case .gpt54mini: return "GPT-5.4 mini"
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
        var args = [
            "analyze", repoURL.path,
            "--format", "json",
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
                args += ["--llm-model", model.rawValue, "--llm-effort", effort.rawValue]
                if fast && model.fastCapable {
                    args += ["--llm-speed", "fast"]
                }
            case .openai:
                args += [
                    "--llm-provider", "openai",
                    "--llm-model", openAIModel.rawValue,
                    "--llm-effort", effort.rawValue,
                ]
                // Fast mode is Claude-only; never emit it for OpenAI.
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
