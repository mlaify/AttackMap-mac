import CryptoKit
import Foundation

/// Where scan reports are written (#6): outside the scanned repo, under
/// `~/Library/Application Support/AttackMap/scans/<name>-<hash>/`, so a scan
/// never dirties the working tree (reports hold secret names and evidence
/// snippets a `git add -A` would commit) and plugins never re-read them.
enum ScanOutputLocation {
    static var baseDirectory: URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return support.appendingPathComponent("AttackMap/scans", isDirectory: true)
    }

    /// Report directory for a single-repo scan; stable per repo path.
    static func reports(for repoURL: URL, base: URL = baseDirectory) -> URL {
        base.appendingPathComponent(key(name: repoURL.lastPathComponent, paths: [repoURL]), isDirectory: true)
            .appendingPathComponent("reports", isDirectory: true)
    }

    /// Output directory for a fleet scan; stable per (ordered) set of repos.
    static func fleet(for repoURLs: [URL], base: URL = baseDirectory) -> URL {
        let name = repoURLs.first.map { "fleet-\($0.lastPathComponent)" } ?? "fleet"
        return base.appendingPathComponent(key(name: name, paths: repoURLs), isDirectory: true)
            .appendingPathComponent("fleet", isDirectory: true)
    }

    private static func key(name: String, paths: [URL]) -> String {
        let joined = paths.map { $0.standardizedFileURL.path }.joined(separator: "\n")
        let digest = SHA256.hash(data: Data(joined.utf8)).prefix(6).map { String(format: "%02x", $0) }.joined()
        let safe = name.unicodeScalars.map { CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0) ? String($0) : "_" }.joined()
        return "\(safe.isEmpty ? "repo" : safe)-\(digest)"
    }
}
