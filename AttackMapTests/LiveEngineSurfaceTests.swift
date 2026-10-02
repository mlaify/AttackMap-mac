import XCTest
@testable import AttackMap

/// End-to-end against the real CLI (#7): baseline rotation → `--baseline`
/// diff, `--pr-comment`, the `--fail-on-new-high` gate, SARIF on disk, the
/// inventory sections, and suppress-file entries written by
/// `SuppressFileWriter` — parsed by core's own parser and applied on rescan.
///
/// Skipped unless ATTACKMAP_CLI points at an executable (CI sets it through
/// TEST_RUNNER_ATTACKMAP_CLI).
final class LiveEngineSurfaceTests: XCTestCase {
    private var cli: URL!
    private var work: URL!
    private var repo: URL!
    private var reports: URL!
    private var previous: URL!

    override func setUpWithError() throws {
        guard let path = ProcessInfo.processInfo.environment["ATTACKMAP_CLI"], !path.isEmpty,
              FileManager.default.isExecutableFile(atPath: path) else {
            throw XCTSkip("ATTACKMAP_CLI not set; skipping the live engine-surface test")
        }
        cli = URL(fileURLWithPath: path)
        work = FileManager.default.temporaryDirectory.appendingPathComponent("attackmap-surface-\(UUID().uuidString)")
        repo = work.appendingPathComponent("repo")
        reports = work.appendingPathComponent("out/reports")
        previous = work.appendingPathComponent("out/previous-report.json")
        try FileManager.default.createDirectory(at: repo.appendingPathComponent(".github/workflows"),
                                                withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: reports, withIntermediateDirectories: true)
        // A fake Stripe-shaped literal for the hard-coded-secret detector,
        // assembled at runtime so the source itself carries no key pattern.
        let fakeKey = ["sk", "live", "51HxAbCdEfGhIjKlMnOpQrStUv"].joined(separator: "_")
        try write("""
        import os
        from flask import Flask, request
        app = Flask(__name__)
        API_KEY = "\(fakeKey)"
        DB_PASSWORD = os.getenv("DB_PASSWORD")

        @app.route("/run", methods=["POST"])
        def run():
            os.system(request.form["cmd"])
            return "ok"

        if __name__ == "__main__":
            app.run(debug=True)
        """, "app.py")
        try write("flask==2.0.1\nrequests>=2.20\n", "requirements.txt")
        try write("""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """, ".github/workflows/ci.yml")
    }

    override func tearDownWithError() throws {
        if let work { try? FileManager.default.removeItem(at: work) }
    }

    private func write(_ text: String, _ name: String) throws {
        try text.write(to: repo.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    /// One scan the way ScanViewModel runs it: rotate, resolve, run.
    private func scan(baseline: BaselineChoice, failOnNewHigh: Bool = false) async throws -> (ScanRunResult, ScanConfig) {
        BaselineSelection.rotate(reportsDirectory: reports, previous: previous)
        var config = ScanConfig(repoURL: repo, outputDirectory: reports)
        config.baselineURL = BaselineSelection.resolve(baseline, previous: previous)
        if config.baselineURL != nil { config.diffOutputURL = reports.appendingPathComponent("attackmap-diff.md") }
        config.failOnNewHigh = failOnNewHigh
        config.prCommentURL = reports.appendingPathComponent(ScanViewModel.prCommentFilename)
        let result = try await ProcessRunner().run(executable: cli, config: config, progressJSON: true) { _ in }
        return (result, config)
    }

    func testBaselineDiffSuppressionAndGate() async throws {
        let caps = CLILocator.capabilities(executable: cli)
        XCTAssertTrue(caps.baseline && caps.diffOutput && caps.failOnNewHigh && caps.prComment)

        // 1. First scan: no previous report → no baseline, but every artifact.
        let (_, first) = try await scan(baseline: .previousScan)
        XCTAssertNil(first.baselineURL)
        let report1 = try Report.load(from: first.reportURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.sarifURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.prCommentURL!.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.diffURL.path))
        let scan1 = try XCTUnwrap(report1.scan)
        XCTAssertEqual(Set(scan1.dependencies.map(\.name)), ["flask", "requests"])
        XCTAssertTrue(scan1.secrets.contains { $0.name == "DB_PASSWORD" && !$0.isLiteral })
        XCTAssertTrue(scan1.secrets.contains { $0.isLiteral })
        XCTAssertTrue(scan1.workflowIssues.contains { $0.kind == "unpinned_action" })
        XCTAssertFalse(report1.analyzersRun.isEmpty)
        let secret = try XCTUnwrap(report1.findings.first { $0.effectiveRuleId == "hardcoded-secret" })
        let debug = try XCTUnwrap(report1.findings.first { $0.effectiveRuleId == "debug-enabled" })

        // 2. Suppress both from "the sheet" into an existing, commented file.
        let target = SuppressFileWriter.targetURL(repoURL: repo)
        try write("# reviewed suppressions\nversion: 1\nsuppress:\n  - rule: unpinned-action\n    reason: \"pinned by renovate\"\n",
                  ".attackmap-suppress.yaml")
        try SuppressFileWriter.append(SuppressRule(
            selector: .rule(secret.effectiveRuleId), reason: "test key: rotated # not live",
            paths: secret.locationFiles, expires: Date().addingTimeInterval(86_400 * 60),
            owner: "platform-team", ticket: "SEC-1"), to: target)
        try SuppressFileWriter.append(SuppressRule(selector: .id(debug.id), reason: "local dev only"), to: target)
        try assertCoreParses(target, expectedCount: 3)

        // 3. Rescan against the previous scan: suppressed, diffed, commented.
        let (_, second) = try await scan(baseline: .previousScan, failOnNewHigh: true)
        XCTAssertEqual(second.baselineURL, previous)
        let report2 = try Report.load(from: second.reportURL)
        let suppressedRules = Set(report2.suppressedFindings.compactMap(\.rule))
        XCTAssertTrue(suppressedRules.isSuperset(of: ["hardcoded-secret", "debug-enabled", "unpinned-action"]), "\(suppressedRules)")
        XCTAssertFalse(report2.findings.contains { $0.id == secret.id || $0.id == debug.id })
        XCTAssertEqual(report2.suppressedFindings.first { $0.rule == "hardcoded-secret" }?.reason,
                       "test key: rotated # not live")
        let diff = try String(contentsOf: second.diffURL, encoding: .utf8)
        XCTAssertFalse(diff.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.prCommentURL!.path))

        // 4. A new HIGH finding trips --fail-on-new-high: exit 1, reports
        //    written, and the runner reports it as a gate result.
        try write("""
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/calc", methods=["POST"])
        def calc():
            return str(eval(request.form["expr"]))
        """, "calc.py")
        let (third, thirdConfig) = try await scan(baseline: .previousScan, failOnNewHigh: true)
        XCTAssertEqual(third.exitCode, 1, third.stderrTail)
        XCTAssertTrue(third.newHighGateFailed)
        XCTAssertNoThrow(try Report.load(from: thirdConfig.reportURL))
        XCTAssertTrue(FileManager.default.fileExists(atPath: thirdConfig.diffURL.path))
    }

    /// Parse with core's own `parse_suppress_text` (the interpreter from the
    /// CLI's shebang) and require zero warnings.
    private func assertCoreParses(_ file: URL, expectedCount: Int) throws {
        let script = try String(contentsOf: cli, encoding: .utf8)
        guard script.hasPrefix("#!"), let firstLine = script.split(separator: "\n").first else {
            throw XCTSkip("CLI isn't a Python entry-point script; can't reach core's parser")
        }
        let python = URL(fileURLWithPath: String(firstLine.dropFirst(2)).trimmingCharacters(in: .whitespaces))
        let process = Process()
        process.executableURL = python
        process.arguments = ["-c", """
        import json, sys
        from attackmap.suppress import parse_suppress_text
        warnings = []
        entries = parse_suppress_text(open(sys.argv[1], encoding="utf-8").read(), ".attackmap-suppress.yaml", warnings)
        print(json.dumps({"warnings": warnings, "entries": [
            {"id": e.id, "rule": e.rule, "path": e.path, "reason": e.reason,
             "expires": e.expires.isoformat() if e.expires else None, "owner": e.owner, "ticket": e.ticket}
            for e in entries]}))
        """, file.path]
        let out = Pipe()
        process.standardOutput = out
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual((parsed["warnings"] as? [String]) ?? ["?"], [])
        let entries = try XCTUnwrap(parsed["entries"] as? [[String: Any]])
        XCTAssertEqual(entries.count, expectedCount)
        let secretEntry = try XCTUnwrap(entries.first { ($0["rule"] as? String) == "hardcoded-secret" })
        XCTAssertEqual(secretEntry["reason"] as? String, "test key: rotated # not live")
        XCTAssertEqual(secretEntry["path"] as? String, "app.py")
        XCTAssertEqual(secretEntry["owner"] as? String, "platform-team")
        XCTAssertEqual(secretEntry["ticket"] as? String, "SEC-1")
        XCTAssertNotNil(secretEntry["expires"] as? String)
        XCTAssertTrue(entries.contains { ($0["id"] as? String)?.count == 16 })
    }
}
