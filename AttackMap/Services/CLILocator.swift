import Foundation

/// Finds the `attackmap` executable. This is a dev tool: it drives the CLI the
/// user already installed (Homebrew / pipx / pip / venv), so resolution order is:
/// explicit override → the login shell's `PATH` → common install locations.
enum CLILocator {
    /// Common install locations (Homebrew, pipx, pip), checked as a fallback.
    static let commonDirectories: [String] = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        (NSString(string: "~/.local/bin").expandingTildeInPath),
    ]

    /// How long the login shell may take to answer (`.zprofile` with nvm/conda
    /// init can be slow; a prompting profile would never answer).
    static let loginShellTimeout: TimeInterval = 3

    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cachedLoginShellPath: URL?

    /// Resolve the `attackmap` binary, or `nil` if it can't be found.
    ///
    /// May spawn the user's login shell (once; the result is cached), so call
    /// it off the main thread — see `locateAsync` and `cachedLocate`.
    static func locate(explicitPath: String? = nil,
                       fileManager: FileManager = .default) -> URL? {
        if let explicit = explicitURL(explicitPath) {
            return fileManager.isExecutableFile(atPath: explicit.path) ? explicit : nil
        }
        if let cached = cacheLock.withLock({ cachedLoginShellPath }),
           fileManager.isExecutableFile(atPath: cached.path) {
            return cached
        }
        if let onPath = whichViaLoginShell(), fileManager.isExecutableFile(atPath: onPath.path) {
            cacheLock.withLock { cachedLoginShellPath = onPath }
            return onPath
        }
        return commonDirectoryMatch(fileManager)
    }

    /// `locate` on a background thread.
    static func locateAsync(explicitPath: String? = nil) async -> URL? {
        await Task.detached(priority: .userInitiated) { locate(explicitPath: explicitPath) }.value
    }

    /// Never spawns a process: the explicit path, the cached login-shell
    /// result, or a common install dir. Safe to call from a view's body.
    static func cachedLocate(explicitPath: String? = nil,
                             fileManager: FileManager = .default) -> URL? {
        if let explicit = explicitURL(explicitPath) {
            return fileManager.isExecutableFile(atPath: explicit.path) ? explicit : nil
        }
        if let cached = cacheLock.withLock({ cachedLoginShellPath }),
           fileManager.isExecutableFile(atPath: cached.path) {
            return cached
        }
        return commonDirectoryMatch(fileManager)
    }

    private static func explicitURL(_ explicitPath: String?) -> URL? {
        guard let explicitPath, !explicitPath.isEmpty else { return nil }
        return URL(fileURLWithPath: (explicitPath as NSString).expandingTildeInPath)
    }

    private static func commonDirectoryMatch(_ fileManager: FileManager) -> URL? {
        for dir in commonDirectories {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("attackmap")
            if fileManager.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        return nil
    }

    /// Which optional `analyze` flags this `attackmap` supports. Older releases
    /// don't recognize newer flags and would exit with a usage error, so the app
    /// feature-detects (one `analyze --help` probe) and adapts:
    /// - `progressJSON` → `--progress-format json` (the M0 NDJSON stream; ≥ 0.4.1)
    /// - `llmSpeed` → `--llm-speed fast` (Fast mode; ≥ the 0.4.3 release)
    /// - `llmProvider` → `--llm-provider openai` (OpenAI/Codex; ≥ the 0.4.3 release)
    /// - `recall` → `--recall` (recall mode; ≥ 0.4.20)
    /// - `triage` → `--triage` (triage mode; ≥ 0.4.15)
    /// - `huntJury` → `--verify-votes` & friends (verify jury; ≥ 0.4.16)
    /// - `suppress` → `--no-suppress` / `--suppress-file` (suppression; ≥ 0.4.7)
    /// - `fleet` → multi-repo fleet scan (variadic `paths`; ≥ 0.4.22). Detected
    ///   by the fleet note the variadic argument's help text carries.
    /// - `baseline` / `diffOutput` / `failOnNewHigh` → the baseline diff
    ///   (`--baseline`, `--diff-output`, `--fail-on-new-high`)
    /// - `prComment` → `--pr-comment <path>` (Markdown PR summary)
    struct Capabilities {
        var progressJSON: Bool
        var llmSpeed: Bool
        var llmProvider: Bool
        var recall: Bool
        var triage: Bool
        var huntJury: Bool
        var suppress: Bool
        var fleet: Bool
        var baseline: Bool = false
        var diffOutput: Bool = false
        var failOnNewHigh: Bool = false
        var prComment: Bool = false
    }

    /// Prefers the structured `attackmap capabilities` JSON (newer CLIs) and
    /// falls back to scanning `analyze --help` for older ones.
    static func capabilities(executable: URL) -> Capabilities {
        if let structured = structuredCapabilities(executable: executable) { return structured }
        let help = analyzeHelpText(executable: executable)
        return Capabilities(
            progressJSON: help.contains("--progress-format"),
            llmSpeed: help.contains("--llm-speed"),
            llmProvider: help.contains("--llm-provider"),
            recall: help.contains("--recall"),
            triage: help.contains("--triage"),
            huntJury: help.contains("--verify-votes"),
            suppress: help.contains("--no-suppress"),
            fleet: help.contains("fleet"),
            baseline: help.contains("--baseline"),
            diffOutput: help.contains("--diff-output"),
            failOnNewHigh: help.contains("--fail-on-new-high"),
            prComment: help.contains("--pr-comment"))
    }

    /// Installed analyzer modules via `attackmap modules --json` (≥ 0.4.4).
    /// Returns `[]` on any failure — an older CLI without `--json` exits
    /// non-zero, in which case the GUI just offers "Automatic" analyzer
    /// selection. Network-free by construction (the `--json` path skips the
    /// remote module-repository lookup).
    static func installedModules(executable: URL) -> [AnalyzerModule] {
        guard let out = ShellRunner.run(executable, ["modules", "--json"], timeout: 30),
              out.status == 0 else { return [] }
        return (try? JSONDecoder().decode([AnalyzerModule].self, from: out.stdout)) ?? []
    }

    /// `attackmap capabilities` output (schema 1).
    struct StructuredCapabilities: Decodable {
        struct Analyze: Decodable {
            let options: [String]
            let multiRepo: Bool
            enum CodingKeys: String, CodingKey { case options, multiRepo = "multi_repo" }
        }
        let schema: Int
        let analyze: Analyze
    }

    static func capabilities(from structured: StructuredCapabilities) -> Capabilities {
        let options = Set(structured.analyze.options)
        return Capabilities(
            progressJSON: options.contains("--progress-format"),
            llmSpeed: options.contains("--llm-speed"),
            llmProvider: options.contains("--llm-provider"),
            recall: options.contains("--recall"),
            triage: options.contains("--triage"),
            huntJury: options.contains("--verify-votes"),
            suppress: options.contains("--no-suppress"),
            fleet: structured.analyze.multiRepo,
            baseline: options.contains("--baseline"),
            diffOutput: options.contains("--diff-output"),
            failOnNewHigh: options.contains("--fail-on-new-high"),
            prComment: options.contains("--pr-comment"))
    }

    private static func structuredCapabilities(executable: URL) -> Capabilities? {
        guard let out = ShellRunner.run(executable, ["capabilities"], timeout: 15), out.status == 0,
              let decoded = try? JSONDecoder().decode(StructuredCapabilities.self, from: out.stdout),
              decoded.schema >= 1 else { return nil }
        return capabilities(from: decoded)
    }

    static func analyzeHelpText(executable: URL) -> String {
        // Wide COLUMNS so Rich doesn't wrap option names across lines.
        var env = ProcessInfo.processInfo.environment
        env["COLUMNS"] = "300"
        return ShellRunner.run(executable, ["analyze", "--help"], environment: env, timeout: 15)?.text ?? ""
    }

    /// Ask the user's login shell to resolve `attackmap` on `PATH`. A GUI app
    /// launched from Finder doesn't inherit the shell's `PATH`, so we spawn the
    /// login shell to honor the user's real environment.
    private static func whichViaLoginShell() -> URL? {
        let shellPath = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        guard let out = ShellRunner.run(URL(fileURLWithPath: shellPath), ["-lc", "command -v attackmap"],
                                        timeout: loginShellTimeout),
              out.status == 0 else { return nil }
        let path = out.text.trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : URL(fileURLWithPath: path)
    }
}
