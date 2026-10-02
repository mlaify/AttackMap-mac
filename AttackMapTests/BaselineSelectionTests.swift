import XCTest
@testable import AttackMap

/// Baseline selection / rotation, the diff + PR-comment flags, capability
/// gating, and export copies (#7).
final class BaselineSelectionTests: XCTestCase {
    private var work: URL!
    private var reports: URL!
    private var previous: URL!

    override func setUpWithError() throws {
        work = FileManager.default.temporaryDirectory.appendingPathComponent("baseline-\(UUID().uuidString)")
        reports = work.appendingPathComponent("repo-abc/reports")
        previous = work.appendingPathComponent("repo-abc/previous-report.json")
        try FileManager.default.createDirectory(at: reports, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: work) }

    private func write(_ text: String, _ url: URL) throws {
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    private func read(_ url: URL) -> String? { try? String(contentsOf: url, encoding: .utf8) }

    func testPreviousReportIsASiblingOfReports() {
        let repo = URL(fileURLWithPath: "/src/app")
        let out = ScanOutputLocation.reports(for: repo, base: work)
        let prev = ScanOutputLocation.previousReport(for: repo, base: work)
        XCTAssertEqual(prev.deletingLastPathComponent(), out.deletingLastPathComponent())
        XCTAssertEqual(prev.lastPathComponent, "previous-report.json")
        XCTAssertFalse(prev.path.hasPrefix(out.path + "/"), "the engine's output dir stays its own")
    }

    func testFirstScanHasNoPreviousBaseline() {
        XCTAssertFalse(BaselineSelection.rotate(reportsDirectory: reports, previous: previous))
        XCTAssertNil(BaselineSelection.resolve(.previousScan, previous: previous))
        XCTAssertNil(BaselineSelection.resolve(.none, previous: previous))
    }

    func testRotationMakesTheLastReportTheDefaultBaseline() throws {
        try write("scan-1", reports.appendingPathComponent("attackmap-report.json"))
        try write("old diff", reports.appendingPathComponent("attackmap-diff.md"))
        try write("old comment", reports.appendingPathComponent("attackmap-pr-comment.md"))

        XCTAssertTrue(BaselineSelection.rotate(reportsDirectory: reports, previous: previous))
        XCTAssertEqual(read(previous), "scan-1")
        XCTAssertFalse(FileManager.default.fileExists(atPath: reports.appendingPathComponent("attackmap-report.json").path),
                       "moved, so a report after the run is guaranteed fresh")
        XCTAssertNil(read(reports.appendingPathComponent("attackmap-diff.md")), "stale per-run artifacts dropped")
        XCTAssertNil(read(reports.appendingPathComponent("attackmap-pr-comment.md")))
        XCTAssertEqual(BaselineSelection.resolve(.previousScan, previous: previous), previous)
        XCTAssertNil(BaselineSelection.resolve(.none, previous: previous))

        // Next scan replaces the older previous report.
        try write("scan-2", reports.appendingPathComponent("attackmap-report.json"))
        XCTAssertTrue(BaselineSelection.rotate(reportsDirectory: reports, previous: previous))
        XCTAssertEqual(read(previous), "scan-2")
    }

    func testFailedScanKeepsThePreviousBaseline() throws {
        try write("scan-1", previous)
        // The last run failed, so there's no current report to rotate.
        XCTAssertFalse(BaselineSelection.rotate(reportsDirectory: reports, previous: previous))
        XCTAssertEqual(read(previous), "scan-1")
        XCTAssertEqual(BaselineSelection.resolve(.previousScan, previous: previous), previous)
    }

    func testCustomBaselineMustExist() throws {
        let custom = work.appendingPathComponent("main-report.json")
        XCTAssertNil(BaselineSelection.resolve(.custom(custom), previous: previous))
        try write("{}", custom)
        XCTAssertEqual(BaselineSelection.resolve(.custom(custom), previous: previous), custom)
    }

    // MARK: Arguments

    private func config() -> ScanConfig {
        ScanConfig(repoURL: URL(fileURLWithPath: "/repo"), outputDirectory: URL(fileURLWithPath: "/out"))
    }

    func testBaselineDiffAndGateFlags() {
        var c = config()
        c.baselineURL = URL(fileURLWithPath: "/prev/previous-report.json")
        c.diffOutputURL = URL(fileURLWithPath: "/out/attackmap-diff.md")
        c.failOnNewHigh = true
        let args = c.arguments(progressJSON: true)
        XCTAssertEqual(value(after: "--baseline", in: args), "/prev/previous-report.json")
        XCTAssertEqual(value(after: "--diff-output", in: args), "/out/attackmap-diff.md")
        XCTAssertTrue(args.contains("--fail-on-new-high"))
        XCTAssertEqual(c.diffURL.path, "/out/attackmap-diff.md")
    }

    func testDiffFlagsNeedABaseline() {
        // The engine rejects --diff-output / --fail-on-new-high without --baseline.
        var c = config()
        c.diffOutputURL = URL(fileURLWithPath: "/out/d.md")
        c.failOnNewHigh = true
        let args = c.arguments(progressJSON: true)
        XCTAssertFalse(args.contains("--baseline"))
        XCTAssertFalse(args.contains("--diff-output"))
        XCTAssertFalse(args.contains("--fail-on-new-high"))
        XCTAssertEqual(c.diffURL.path, "/out/d.md")
        XCTAssertEqual(config().diffURL.path, "/out/attackmap-diff.md")
    }

    func testPRCommentIsIndependentOfBaseline() {
        var c = config()
        c.prCommentURL = URL(fileURLWithPath: "/out/attackmap-pr-comment.md")
        XCTAssertEqual(value(after: "--pr-comment", in: c.arguments(progressJSON: false)), "/out/attackmap-pr-comment.md")
        XCTAssertFalse(config().arguments(progressJSON: false).contains("--pr-comment"))
        XCTAssertFalse(c.fleetArguments(paths: [URL(fileURLWithPath: "/a"), URL(fileURLWithPath: "/b")],
                                        progressJSON: false).contains("--pr-comment"))
    }

    func testCapabilitiesGateTheBaselineFlags() throws {
        let json = #"{"schema": 1, "analyze": {"options": ["--baseline", "--diff-output", "--fail-on-new-high", "--pr-comment"], "multi_repo": false}}"#
        let structured = try JSONDecoder().decode(CLILocator.StructuredCapabilities.self, from: Data(json.utf8))
        let caps = CLILocator.capabilities(from: structured)
        XCTAssertTrue(caps.baseline && caps.diffOutput && caps.failOnNewHigh && caps.prComment)

        let old = #"{"schema": 1, "analyze": {"options": ["--recall"], "multi_repo": false}}"#
        let oldCaps = CLILocator.capabilities(from: try JSONDecoder().decode(CLILocator.StructuredCapabilities.self, from: Data(old.utf8)))
        XCTAssertFalse(oldCaps.baseline || oldCaps.diffOutput || oldCaps.failOnNewHigh || oldCaps.prComment)
    }

    func testNewHighGateIsRecognizedFromStderr() {
        let tripped = ScanRunResult(exitCode: 1, reportURL: reports, stdout: "",
                                    stderrTail: "New HIGH findings introduced (failing per --fail-on-new-high):\n  - X")
        XCTAssertTrue(tripped.newHighGateFailed)
        let clean = ScanRunResult(exitCode: 0, reportURL: reports, stdout: "", stderrTail: "")
        XCTAssertFalse(clean.newHighGateFailed)
        let otherFailure = ScanRunResult(exitCode: 1, reportURL: reports, stdout: "", stderrTail: "Traceback")
        XCTAssertFalse(otherFailure.newHighGateFailed)
    }

    /// The runner accepts exit 1 only when told to (the gate) — any other
    /// non-zero exit still fails the scan.
    func testRunnerToleratesOnlyTheGateExit() async throws {
        let exe = work.appendingPathComponent("fake-attackmap")
        let report = work.appendingPathComponent("r.json")
        try write("{}", report)
        try write("#!/bin/sh\necho 'New HIGH findings introduced (failing per --fail-on-new-high):' >&2\nexit 1\n", exe)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        let runner = ProcessRunner()
        let result = try await runner.run(
            executable: exe, arguments: [], currentDirectory: work, successFile: report,
            environment: [:], tolerateExit: { code, err in code == 1 && ScanRunResult.isNewHighGateFailure(stderrTail: err) },
            onProgress: { _ in })
        XCTAssertTrue(result.newHighGateFailed)
        do {
            _ = try await runner.run(executable: exe, arguments: [], currentDirectory: work,
                                     successFile: report, environment: [:], onProgress: { _ in })
            XCTFail("exit 1 must fail without the gate")
        } catch ScanRunError.nonZeroExit(let code, _, _) {
            XCTAssertEqual(code, 1)
        }
    }

    func testExportCopyReplacesExistingFile() throws {
        let source = work.appendingPathComponent("attackmap-report.sarif")
        let dest = work.appendingPathComponent("export/out.sarif")
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        try write("v2", source)
        try ReportExporter.copy(source, to: dest)
        XCTAssertEqual(read(dest), "v2")
        try write("v3", source)
        try ReportExporter.copy(source, to: dest)
        XCTAssertEqual(read(dest), "v3")
        try ReportExporter.copy(source, to: source)
        XCTAssertEqual(read(source), "v3", "copying onto itself is a no-op")
    }

    private func value(after flag: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
}
