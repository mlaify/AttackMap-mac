import XCTest

/// Drives the real app (XCUITest) so releases don't depend on clicking
/// through it by hand. Every section is opened and screenshotted (attachments
/// in the .xcresult); the live test scans a repo with the real CLI.
final class AttackMapUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ arguments: [String]) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launch()
        return app
    }

    private func screenshot(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.windows.firstMatch.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    /// A static text by its label (identifiers may be inherited from a container).
    private func text(_ app: XCUIApplication, _ label: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    private func fixture(_ name: String) throws -> String {
        try XCTUnwrap(Bundle(for: Self.self).path(forResource: name, ofType: "json"), "missing fixture \(name).json")
    }

    /// A report with findings and attack chains: every sidebar section opens,
    /// findings list and select, the chains section shows the chain's steps.
    func testReportNavigationAcrossEverySection() throws {
        let app = launch(["-UITestReport", try fixture("ui-report")])
        XCTAssertTrue(app.staticTexts["scanDone"].waitForExistence(timeout: 20), "report didn't load")

        let sections = [
            "Overview", "Findings", "Exploitability", "Attack chains", "Attack paths", "Attack surface",
            "Diff", "Dependencies", "Secrets", "CI workflows", "Data flows", "Analyzers", "Diagrams", "Review",
            "AI Review",
        ]
        for name in sections {
            let item = app.descendants(matching: .any)["section.\(name)"]
            XCTAssertTrue(item.waitForExistence(timeout: 10), "sidebar has no \(name)")
            item.click()
            screenshot(app, name)
        }

        app.descendants(matching: .any)["section.Findings"].click()
        let rows = app.descendants(matching: .any).matching(identifier: "findingRow")
        XCTAssertTrue(rows.firstMatch.waitForExistence(timeout: 10), "no finding rows")
        XCTAssertGreaterThanOrEqual(rows.count, 5)
        rows.firstMatch.click()
        XCTAssertFalse(text(app, "Select a finding").exists, "selecting a finding showed no detail")
        screenshot(app, "Finding detail")

        app.descendants(matching: .any)["section.Attack chains"].click()
        XCTAssertTrue(app.descendants(matching: .any)["chainsList"].waitForExistence(timeout: 10))
        let steps = app.descendants(matching: .any).matching(identifier: "chainStep")
        XCTAssertGreaterThanOrEqual(steps.count, 2, "chain steps not shown")
        XCTAssertTrue(text(app, "pr-target-checkout").exists, "the chain's first step isn't shown")
    }

    /// The whole loop with the real CLI: pick a repo, scan, read findings.
    /// Runs when TEST_RUNNER_ATTACKMAP_CLI points at an installed attackmap.
    func testLiveScanWithTheCLI() throws {
        guard let cli = ProcessInfo.processInfo.environment["ATTACKMAP_CLI"], !cli.isEmpty else {
            throw XCTSkip("set TEST_RUNNER_ATTACKMAP_CLI to run the live scan")
        }
        let repo = FileManager.default.temporaryDirectory.appendingPathComponent("am-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        try """
        from flask import Flask, request
        import sqlite3
        app = Flask(__name__)

        @app.route('/search')
        def search():
            return sqlite3.connect('d').execute('SELECT * FROM t WHERE n = ' + request.args['q']).fetchall()
        """.write(to: repo.appendingPathComponent("app.py"), atomically: true, encoding: .utf8)

        let app = launch(["-UITestRepo", repo.path, "-cliPathOverride", cli])
        let done = app.staticTexts["scanDone"]
        let failed = app.staticTexts["scanFailed"]
        let deadline = Date().addingTimeInterval(180)
        while Date() < deadline, !done.exists, !failed.exists { _ = done.waitForExistence(timeout: 2) }
        XCTAssertFalse(failed.exists, "scan failed: \(failed.exists ? failed.label : "")")
        XCTAssertTrue(done.exists, "scan didn't finish")
        screenshot(app, "Live scan")
        app.descendants(matching: .any)["section.Findings"].click()
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "findingRow").firstMatch.waitForExistence(timeout: 10))
    }
}
