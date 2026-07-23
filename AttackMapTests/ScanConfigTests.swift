import XCTest
@testable import AttackMap

/// Verifies the `attackmap analyze …` argument vector, focusing on the LLM
/// provider/model/effort/speed translation.
final class ScanConfigTests: XCTestCase {
    private func config(
        modules: [String] = [],
        llmMode: ScanConfig.LLMMode = .review,
        provider: ScanConfig.Provider = .claude,
        model: ScanConfig.LLMModel = .opus48,
        openAIModel: ScanConfig.OpenAIModel = .codex,
        effort: ScanConfig.Effort = .high,
        fast: Bool = false
    ) -> ScanConfig {
        ScanConfig(
            repoURL: URL(fileURLWithPath: "/repo"),
            outputDirectory: URL(fileURLWithPath: "/out"),
            modules: modules,
            llmMode: llmMode,
            provider: provider,
            model: model,
            openAIModel: openAIModel,
            effort: effort,
            fast: fast)
    }

    func testEmptyModulesEmitsNoModuleFlag() {
        let args = config(modules: []).arguments(progressJSON: true)
        XCTAssertFalse(args.contains("--module"))
    }

    func testSelectedModulesEmitOneFlagEach() {
        let args = config(modules: ["rust", "python-web"]).arguments(progressJSON: true)
        // One --module per selected analyzer, sorted for determinism.
        let moduleValues = args.enumerated()
            .filter { $0.element == "--module" }
            .map { args[$0.offset + 1] }
        XCTAssertEqual(moduleValues, ["python-web", "rust"])
    }

    func testClaudeOmitsProviderFlagForBackwardCompatibility() {
        let args = config(provider: .claude, model: .sonnet5).arguments(progressJSON: true)
        XCTAssertFalse(args.contains("--llm-provider"))
        XCTAssertEqual(value(after: "--llm-model", in: args), "claude-sonnet-5")
        XCTAssertEqual(value(after: "--llm-effort", in: args), "high")
    }

    func testClaudeFastEmittedOnlyOnCapableModel() {
        let capable = config(model: .opus48, fast: true).arguments(progressJSON: true)
        XCTAssertEqual(value(after: "--llm-speed", in: capable), "fast")

        let incapable = config(model: .sonnet5, fast: true).arguments(progressJSON: true)
        XCTAssertFalse(incapable.contains("--llm-speed"))
    }

    func testOpenAIEmitsProviderAndModelAndNoFast() {
        let args = config(
            provider: .openai, openAIModel: .gpt55, effort: .max, fast: true
        ).arguments(progressJSON: true)
        XCTAssertEqual(value(after: "--llm-provider", in: args), "openai")
        XCTAssertEqual(value(after: "--llm-model", in: args), "gpt-5.5")
        XCTAssertEqual(value(after: "--llm-effort", in: args), "max")
        // Fast mode is Claude-only; never emitted for OpenAI even if toggled.
        XCTAssertFalse(args.contains("--llm-speed"))
    }

    func testOpenAIDefaultModelIsCodex() {
        let args = config(provider: .openai).arguments(progressJSON: true)
        XCTAssertEqual(value(after: "--llm-model", in: args), "gpt-5-codex")
    }

    func testNoLLMModeEmitsNoLLMFlags() {
        let args = config(llmMode: .none, provider: .openai).arguments(progressJSON: true)
        XCTAssertFalse(args.contains("--llm-provider"))
        XCTAssertFalse(args.contains("--llm-model"))
    }

    // MARK: Recall / triage / suppression / jury (0.4.7–0.4.25 features)

    func testRecallEmitsFlag() {
        var c = config(llmMode: .none)
        c.recall = true
        XCTAssertTrue(c.arguments(progressJSON: true).contains("--recall"))
    }

    func testTriageModeEmitsTriageFlag() {
        let args = config(llmMode: .triage).arguments(progressJSON: true)
        XCTAssertTrue(args.contains("--triage"))
        XCTAssertFalse(args.contains("--llm"))
        XCTAssertFalse(args.contains("--hunt"))
    }

    func testSuppressionFlags() {
        var c = config(llmMode: .none)
        c.noSuppress = true
        c.suppressFileURL = URL(fileURLWithPath: "/repo/.attackmap-suppress.yaml")
        let args = c.arguments(progressJSON: true)
        XCTAssertTrue(args.contains("--no-suppress"))
        XCTAssertEqual(value(after: "--suppress-file", in: args), "/repo/.attackmap-suppress.yaml")
    }

    func testDefaultJuryEmitsNoKnobs() {
        // An untouched jury matches the engine defaults, so no flags appear.
        let args = config(llmMode: .huntVerify).arguments(progressJSON: true)
        for flag in ["--verify-votes", "--hunt-lenses", "--hunt-rounds", "--hunt-budget"] {
            XCTAssertFalse(args.contains(flag), "\(flag) should be omitted at defaults")
        }
    }

    func testJuryKnobsEmittedWhenChanged() {
        var c = config(llmMode: .huntVerify)
        c.jury = ScanConfig.Jury(verifyVotes: 5, lenses: 3, rounds: 2, budget: 100_000)
        let args = c.arguments(progressJSON: true)
        XCTAssertEqual(value(after: "--verify-votes", in: args), "5")
        XCTAssertEqual(value(after: "--hunt-lenses", in: args), "3")
        XCTAssertEqual(value(after: "--hunt-rounds", in: args), "2")
        XCTAssertEqual(value(after: "--hunt-budget", in: args), "100000")
    }

    func testJuryKnobsNotEmittedOutsideHuntVerify() {
        var c = config(llmMode: .hunt)   // hunt without verify
        c.jury = ScanConfig.Jury(verifyVotes: 5, lenses: 3, rounds: 2, budget: 0)
        let args = c.arguments(progressJSON: true)
        XCTAssertFalse(args.contains("--verify-votes"))
        XCTAssertFalse(args.contains("--hunt-lenses"))
    }

    // MARK: Fleet arguments (multi-repo, #146)

    func testFleetArgumentsListEachPathAndOmitLLM() {
        var c = config(llmMode: .review)   // LLM mode is ignored for fleets
        c.recall = true
        c.runCVE = true
        let paths = [URL(fileURLWithPath: "/a"), URL(fileURLWithPath: "/b")]
        let args = c.fleetArguments(paths: paths, progressJSON: true)
        XCTAssertEqual(args.first, "analyze")
        XCTAssertTrue(args.contains("/a"))
        XCTAssertTrue(args.contains("/b"))
        XCTAssertTrue(args.contains("--recall"))
        XCTAssertTrue(args.contains("--cve"))
        XCTAssertEqual(value(after: "--output", in: args), "/out")
        // Single-repo-only flags must never leak into a fleet run.
        XCTAssertFalse(args.contains("--llm"))
        XCTAssertFalse(args.contains("--llm-model"))
        XCTAssertFalse(args.contains("--baseline"))
    }

    private func value(after flag: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
}
