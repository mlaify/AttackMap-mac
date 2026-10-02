import Foundation

/// Which report a single-repo scan diffs against (`--baseline`).
enum BaselineChoice: Hashable {
    /// No baseline: no diff, no `--fail-on-new-high`.
    case none
    /// The report from this repo's previous scan in the app (the default).
    case previousScan
    /// A report the user picked (e.g. one exported from CI on `main`).
    case custom(URL)

    var label: String {
        switch self {
        case .none: return "None"
        case .previousScan: return "Previous scan"
        case .custom(let url): return url.lastPathComponent
        }
    }
}

/// Baseline bookkeeping, kept free of UI/state so it is unit-testable:
/// rotating the last report aside before a rescan, and resolving the user's
/// choice to a concrete file (or none).
enum BaselineSelection {
    /// Generated files that describe *one* run and must not outlive it: a
    /// stale diff / PR comment would otherwise be shown for a scan that didn't
    /// produce them.
    static let perRunArtifacts = ["attackmap-diff.md", "attackmap-pr-comment.md"]

    /// Before a rescan: move `<reports>/attackmap-report.json` to `previous`
    /// (replacing an older one), and drop per-run artifacts. Moving rather
    /// than copying also means a report present after the run is guaranteed
    /// fresh. Returns whether a report was set aside. When there is no
    /// current report (first scan, or the last one failed) the existing
    /// `previous` is kept, so a failed run never loses the baseline.
    @discardableResult
    static func rotate(reportsDirectory: URL, previous: URL,
                       fileManager: FileManager = .default) -> Bool {
        for name in perRunArtifacts {
            try? fileManager.removeItem(at: reportsDirectory.appendingPathComponent(name))
        }
        let current = reportsDirectory.appendingPathComponent("attackmap-report.json")
        guard fileManager.fileExists(atPath: current.path) else { return false }
        try? fileManager.createDirectory(at: previous.deletingLastPathComponent(),
                                         withIntermediateDirectories: true)
        try? fileManager.removeItem(at: previous)
        do {
            try fileManager.moveItem(at: current, to: previous)
            return true
        } catch {
            return false
        }
    }

    /// The `--baseline` file for `choice`, or `nil` when there is nothing
    /// usable (no previous scan yet, or the picked file has gone).
    static func resolve(_ choice: BaselineChoice, previous: URL,
                        fileManager: FileManager = .default) -> URL? {
        switch choice {
        case .none:
            return nil
        case .previousScan:
            return fileManager.fileExists(atPath: previous.path) ? previous : nil
        case .custom(let url):
            return fileManager.fileExists(atPath: url.path) ? url : nil
        }
    }
}
