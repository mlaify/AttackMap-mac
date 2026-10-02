import Foundation

/// A GUI app launched from Finder/Xcode inherits a minimal `PATH` (typically
/// just `/usr/bin:/bin:/usr/sbin:/sbin`). That's enough to find `attackmap`
/// (we resolve it explicitly), but not the tools *it* shells out to — notably
/// the `claude` CLI backend in `~/.local/bin`, whose absence makes `--llm` /
/// `--hunt` / `--remediate` silently skip. We resolve the user's real login
/// shell `PATH` and hand it to the child so those lookups succeed.
enum LoginShellEnvironment {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var cached: String??

    /// The login shell's `PATH`, or `nil` if it can't be resolved within
    /// `CLILocator.loginShellTimeout`. Resolved once per app run and cached,
    /// instead of spawning a login shell for every scan (#4). Call off the
    /// main thread.
    static func path() -> String? {
        if let cached = lock.withLock({ cached }) { return cached }
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        var value: String?
        if let out = ShellRunner.run(URL(fileURLWithPath: shell), ["-lc", "printf %s \"$PATH\""],
                                     timeout: CLILocator.loginShellTimeout),
           out.status == 0 {
            let text = out.text.trimmingCharacters(in: .whitespacesAndNewlines)
            value = text.isEmpty ? nil : text
        }
        lock.withLock { cached = .some(value) }
        return value
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
