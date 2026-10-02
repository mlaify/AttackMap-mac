import XCTest
@testable import AttackMap

/// Runs the real `attackmap` CLI exactly as the app does (ScanConfig.arguments)
/// and checks the contract the app depends on: the NDJSON progress stream on
/// stderr, attackmap-report.json decoding, and the Markdown diagram files.
///
/// Skipped unless ATTACKMAP_CLI points at an executable (CI sets it through
/// TEST_RUNNER_ATTACKMAP_CLI after installing the CLI from AttackMap main).
final class LiveCLIContractTests: XCTestCase {
    private var cli: URL!
    private var work: URL!

    override func setUpWithError() throws {
        guard let path = ProcessInfo.processInfo.environment["ATTACKMAP_CLI"], !path.isEmpty,
              FileManager.default.isExecutableFile(atPath: path) else {
            throw XCTSkip("ATTACKMAP_CLI not set; skipping the live CLI contract test")
        }
        cli = URL(fileURLWithPath: path)
        work = FileManager.default.temporaryDirectory
            .appendingPathComponent("attackmap-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let work { try? FileManager.default.removeItem(at: work) }
    }

    func testAnalyzeContract() throws {
        let repo = work.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        try """
        import os
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/run", methods=["POST"])
        def run():
            os.system(request.form["cmd"])
            return "ok"
        """.write(to: repo.appendingPathComponent("app.py"), atomically: true, encoding: .utf8)

        let out = work.appendingPathComponent("out")
        let config = ScanConfig(repoURL: repo, outputDirectory: out)

        let process = Process()
        process.executableURL = cli
        process.arguments = config.arguments(progressJSON: true)
        let stderr = Pipe()
        process.standardError = stderr
        let stdoutURL = work.appendingPathComponent("stdout.log")
        FileManager.default.createFile(atPath: stdoutURL.path, contents: nil)
        process.standardOutput = try FileHandle(forWritingTo: stdoutURL)
        try process.run()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let errText = String(decoding: errData, as: UTF8.self)
        let outText = (try? String(contentsOf: stdoutURL, encoding: .utf8)) ?? ""
        XCTAssertEqual(process.terminationStatus, 0, "stderr:\n\(errText)\nstdout:\n\(outText)")

        let events = errText.split(separator: "\n").compactMap { ProgressEvent.decode(line: String($0)) }
        XCTAssertTrue(events.contains { $0.kind == .begin }, "no begin event in: \(errText)")
        XCTAssertTrue(events.contains { $0.kind == .done }, "no done event in: \(errText)")
        XCTAssertTrue(events.allSatisfy { $0.version == 1 })

        let report = try Report.load(from: config.reportURL)
        XCTAssertEqual(report.scan?.routes.count, 1)
        XCTAssertFalse(report.findings.isEmpty)
        XCTAssertFalse(report.exploitability.isEmpty)
        for name in ["attackmap-paths.md", "attackmap-topology.md"] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: out.appendingPathComponent(name).path), "\(name) missing")
        }
    }
}
