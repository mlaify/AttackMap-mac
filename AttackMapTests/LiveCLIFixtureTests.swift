import XCTest
@testable import AttackMap

/// Decodes reports produced by attackmap 0.4.31 / main (2026-10-01) run exactly
/// the way ScanConfig.arguments()/fleetArguments() build the command line.
/// The app's decoders are tolerant (`try?` per field), so a schema drift shows
/// up as silently-empty data rather than a throw — these tests compare decoded
/// counts against the raw JSON to catch that.
final class LiveCLIFixtureTests: XCTestCase {
    private func url(_ name: String) throws -> URL {
        try XCTUnwrap(Bundle(for: Self.self).url(forResource: name, withExtension: "json"), "\(name).json missing")
    }

    private func rawFindings(_ name: String) throws -> [[String: Any]] {
        let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: url(name))) as? [String: Any]
        return try XCTUnwrap(obj?["findings"] as? [[String: Any]])
    }

    func testLivePythonReportDecodes() throws {
        let report = try Report.load(from: url("live-report"))
        XCTAssertEqual(report.findings.count, 9)
        XCTAssertEqual(report.suppressedFindings.count, 1)
        XCTAssertEqual(report.suppressedFindings.first?.rule, "debug-enabled")
        XCTAssertEqual(report.attackPaths.count, 3)
        XCTAssertEqual(report.attackSurfaces.count, 5)
        XCTAssertEqual(report.exploitability.count, 15)
        XCTAssertEqual(report.scan?.routes.count, 5)
        XCTAssertEqual(report.scan?.languages, ["python"])
        XCTAssertNotNil(report.defensiveReviewMarkdown)
        for f in report.findings {
            XCTAssertNotEqual(f.title, "(untitled)")
            XCTAssertNotEqual(Severity(f.severity), .unknown)
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertNotNil(f.score)
        }
        for e in report.exploitability {
            XCTAssertFalse(e.factors.isEmpty)
            XCTAssertNotNil(e.factors.first?.name)
        }
    }

    func testLiveJavaScriptReportDecodes() throws {
        let report = try Report.load(from: url("live-report-js"))
        XCTAssertEqual(report.findings.count, 4)
        XCTAssertEqual(report.attackSurfaces.count, 3)
        XCTAssertEqual(report.exploitability.count, 9)
        XCTAssertEqual(report.scan?.languages, ["javascript"])
    }

    /// The engine emits attack_techniques as objects
    /// ({technique_id, name, tactic, url}); the app decodes [String].
    func testAttackTechniquesSurvive() throws {
        let report = try Report.load(from: url("live-report"))
        let raw = try rawFindings("live-report")
        let rawWithTechniques = raw.filter { !(($0["attack_techniques"] as? [Any]) ?? []).isEmpty }.count
        XCTAssertEqual(rawWithTechniques, 6)
        XCTAssertEqual(report.findings.filter { !$0.attackTechniques.isEmpty }.count, rawWithTechniques,
                       "attack_techniques silently dropped by the decoder")
    }

    func testLiveFleetSummaryDecodes() throws {
        let fleet = try FleetSummary.load(from: url("live-fleet-summary"))
        XCTAssertEqual(fleet.repoCount, 2)
        XCTAssertEqual(fleet.totalFindings, 14)
        XCTAssertEqual(fleet.repos.map(\.repoId), ["repoa", "repob"])
        XCTAssertEqual(fleet.repos.first?.count(.high), 6)
        XCTAssertEqual(fleet.crossRepoLinks.count, 1)
        XCTAssertEqual(fleet.crossRepoLinks.first?.serverLocation, "app.py:7")
        XCTAssertEqual(fleet.crossBoundaryFlows.count, 1)
        XCTAssertEqual(fleet.crossBoundaryFlows.first?.basis, "taint")
        XCTAssertEqual(fleet.crossRepoSignalCount, 1)
    }
}
