import Foundation

/// Finds the `attackmap` executable. This is a dev tool: it drives the CLI the
/// user already installed (brew / pipx / venv), so resolution order is:
/// explicit override → the login shell's `PATH` → common install locations.
enum CLILocator {
    /// Locations Homebrew / pipx install into, checked as a fallback.
    static let commonDirectories: [String] = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        (NSString(string: "~/.local/bin").expandingTildeInPath),
    ]

    /// Resolve the `attackmap` binary, or `nil` if it can't be found.
    static func locate(explicitPath: String? = nil,
                       fileManager: FileManager = .default) -> URL? {
        if let explicitPath, !explicitPath.isEmpty {
            let url = URL(fileURLWithPath: (explicitPath as NSString).expandingTildeInPath)
            return fileManager.isExecutableFile(atPath: url.path) ? url : nil
        }
        if let onPath = whichViaLoginShell(), fileManager.isExecutableFile(atPath: onPath.path) {
            return onPath
        }
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
    struct Capabilities {
        var progressJSON: Bool
        var llmSpeed: Bool
        var llmProvider: Bool
    }

    static func capabilities(executable: URL) -> Capabilities {
        let help = analyzeHelpText(executable: executable)
        return Capabilities(
            progressJSON: help.contains("--progress-format"),
            llmSpeed: help.contains("--llm-speed"),
            llmProvider: help.contains("--llm-provider"))
    }

    /// Installed analyzer modules via `attackmap modules --json` (≥ 0.4.4).
    /// Returns `[]` on any failure — an older CLI without `--json` exits
    /// non-zero, in which case the GUI just offers "Automatic" analyzer
    /// selection. Network-free by construction (the `--json` path skips the
    /// remote module-repository lookup).
    static func installedModules(executable: URL) -> [AnalyzerModule] {
        let process = Process()
        process.executableURL = executable
        process.arguments = ["modules", "--json"]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return []
        }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return [] }
        return (try? JSONDecoder().decode([AnalyzerModule].self, from: data)) ?? []
    }

    private static func analyzeHelpText(executable: URL) -> String {
        let process = Process()
        process.executableURL = executable
        process.arguments = ["analyze", "--help"]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return ""
        }
        process.waitUntilExit()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: data, as: UTF8.self)
    }

    /// Ask the user's login shell to resolve `attackmap` on `PATH`. A GUI app
    /// launched from Finder doesn't inherit the shell's `PATH`, so we spawn the
    /// login shell to honor the user's real environment.
    private static func whichViaLoginShell() -> URL? {
        let shellPath = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: shellPath)
        process.arguments = ["-lc", "command -v attackmap"]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        let path = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : URL(fileURLWithPath: path)
    }
}
