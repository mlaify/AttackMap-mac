import Foundation

/// A GUI app launched from Finder/Xcode inherits a minimal `PATH` (typically
/// just `/usr/bin:/bin:/usr/sbin:/sbin`). That's enough to find `attackmap`
/// (we resolve it explicitly), but not the tools *it* shells out to — notably
/// the `claude` CLI backend in `~/.local/bin`, whose absence makes `--llm` /
/// `--hunt` / `--remediate` silently skip. We resolve the user's real login
/// shell `PATH` and hand it to the child so those lookups succeed.
enum LoginShellEnvironment {
    /// The login shell's `PATH`, or `nil` if it can't be resolved.
    static func path() -> String? {
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: shell)
        process.arguments = ["-lc", "printf %s \"$PATH\""]
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
        let value = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    /// A `PATH` that unions the login shell's entries with `current` (login
    /// first, de-duped), plus common install dirs as a backstop.
    static func mergedPath(with current: String?) -> String {
        let fallback = ["/opt/homebrew/bin", "/usr/local/bin",
                        (NSString(string: "~/.local/bin").expandingTildeInPath)]
        let login = (path()?.split(separator: ":").map(String.init)) ?? []
        let existing = current?.split(separator: ":").map(String.init) ?? []
        var seen = Set<String>()
        var merged: [String] = []
        for dir in login + existing + fallback where seen.insert(dir).inserted {
            merged.append(dir)
        }
        return merged.joined(separator: ":")
    }
}
