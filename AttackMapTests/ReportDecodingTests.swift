import XCTest
@testable import AttackMap

/// Decodes a real `attackmap-report.json` fixture (generated from an actual
/// scan of a vulnerable Flask app) to lock the Codable models against the
/// engine's output shape.
final class ReportDecodingTests: XCTestCase {
    private func fixtureURL() throws -> URL {
        let url = Bundle(for: Self.self).url(forResource: "sample-report", withExtension: "json")
        return try XCTUnwrap(url, "sample-report.json missing from the test bundle")
    }

    func testDecodesRealReport() throws {
        let report = try Report.load(from: fixtureURL())

        XCTAssertEqual(report.findings.count, 2)
        XCTAssertEqual(report.exploitability.count, 1)
        XCTAssertEqual(report.attackPaths.count, 1)
        XCTAssertEqual(report.attackSurfaces.count, 2)
        XCTAssertEqual(report.scan?.routes.count, 2)
        XCTAssertEqual(report.scan?.languages, ["python"])
    }

    func testFindingsSortMostSevereFirst() throws {
        let report = try Report.load(from: fixtureURL())
        let top = try XCTUnwrap(report.findingsByPriority.first)
        XCTAssertEqual(Severity(top.severity), .high)
        XCTAssertFalse(top.title.isEmpty)
    }

    func testExploitabilityCarriesFactors() throws {
        let report = try Report.load(from: fixtureURL())
        let score = try XCTUnwrap(report.exploitability.first)
        XCTAssertEqual(score.score, 100)
        XCTAssertEqual(score.sinkKind, "subprocess_shell")
        XCTAssertFalse(score.factors.isEmpty)
    }

    func testTolerantDecodeOfEmptyReport() throws {
        let report = try JSONDecoder().decode(Report.self, from: Data("{}".utf8))
        XCTAssertTrue(report.findings.isEmpty)
        XCTAssertNil(report.scan)
    }
}
