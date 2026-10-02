import XCTest
@testable import AttackMap

/// Scan output location, watcher filtering and watch-mode deltas (#6).
final class ScanOutputTests: XCTestCase {
    func testReportsLiveOutsideTheRepo() {
        let repo = URL(fileURLWithPath: "/Users/me/src/my repo")
        let base = URL(fileURLWithPath: "/tmp/am-base")
        let out = ScanOutputLocation.reports(for: repo, base: base)
        XCTAssertFalse(out.path.hasPrefix(repo.path))
        XCTAssertTrue(out.path.hasPrefix(base.path + "/my_repo-"))
        XCTAssertEqual(out, ScanOutputLocation.reports(for: repo, base: base), "stable per repo")
        XCTAssertNotEqual(out, ScanOutputLocation.reports(for: URL(fileURLWithPath: "/Users/me/other/my repo"), base: base))
        let fleet = ScanOutputLocation.fleet(for: [repo, URL(fileURLWithPath: "/x/b")], base: base)
        XCTAssertNotEqual(fleet.deletingLastPathComponent(), out.deletingLastPathComponent())
    }

    func testWatcherFiresForRepoUnderIgnoredDirName() {
        let watcher = RepoWatcher()
        watcher.setRoot(URL(fileURLWithPath: "/tmp/build/repo"))
        XCTAssertTrue(watcher.isRelevant(path: "/tmp/build/repo/app.py"))
        XCTAssertTrue(watcher.isRelevant(path: "/private/tmp/build/repo/src/app.py"))
        XCTAssertFalse(watcher.isRelevant(path: "/tmp/build/repo/node_modules/x/index.js"))
        XCTAssertFalse(watcher.isRelevant(path: "/tmp/build/repo/build/out.o"))
        XCTAssertFalse(watcher.isRelevant(path: "/tmp/build/repo/.git/index"))
    }

    func testSecondInstanceInSameFindingCountsAsNew() throws {
        func report(_ evidence: [String]) throws -> Report {
            let json: [String: Any] = ["findings": [[
                "id": "unauthenticated-route", "title": "Unauthenticated route", "severity": "high",
                "confidence": "medium", "evidence": evidence,
            ]]]
            let url = FileManager.default.temporaryDirectory.appendingPathComponent("r-\(UUID()).json")
            try JSONSerialization.data(withJSONObject: json).write(to: url)
            defer { try? FileManager.default.removeItem(at: url) }
            return try Report.load(from: url)
        }
        let before = ScanViewModel.deltaKeys(try report(["POST /a (app.py:3)"]))
        let after = ScanViewModel.deltaKeys(try report(["POST /a (app.py:3)", "POST /b (app.py:9)"]))
        XCTAssertEqual(after.subtracting(before).count, 1)
        XCTAssertEqual(before.subtracting(after).count, 0)
    }
}
