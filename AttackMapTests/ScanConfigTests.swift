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

    private func value(after flag: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
}
