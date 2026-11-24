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

final class AttackChainDecodingTests: XCTestCase {
    func testDecodesChainsAndSchemaVersion() throws {
        let json = """
        {"schema_version": "1.1.0", "findings": [], "attack_chains": [{
          "id": "chain:1", "impact": "secrets", "likelihood": 0.64, "start": ["fork_pr"],
          "steps": [
            {"id": "a", "rule_id": "pr-target-checkout", "title": "PR checkout", "grants": ["ci_code_exec"],
             "requires": ["fork_pr"], "evidence_ids": ["a"], "confidence": 0.8, "precondition_notes": [],
             "location": {"file": ".github/workflows/pr.yml", "line": 9}},
            {"id": "b", "rule_id": "secret-in-run", "title": "Secret in run", "grants": ["secrets"],
             "requires": ["ci_code_exec"], "evidence_ids": ["b"], "confidence": 0.8,
             "precondition_notes": ["assumes x"], "location": null}
          ]}]}
        """
        let report = try JSONDecoder().decode(Report.self, from: Data(json.utf8))
        XCTAssertEqual(report.schemaVersion, "1.1.0")
        let chain = try XCTUnwrap(report.attackChains.first)
        XCTAssertEqual(chain.steps.map(\.ruleId), ["pr-target-checkout", "secret-in-run"])
        XCTAssertEqual(chain.steps[0].place, ".github/workflows/pr.yml:9")
        XCTAssertNil(chain.steps[1].place)
        XCTAssertEqual(chain.steps[1].preconditionNotes, ["assumes x"])
        XCTAssertEqual(AttackChain.label("ci_code_exec"), "Ci Code Exec")
    }

    func testOlderReportsHaveNoChains() throws {
        let report = try JSONDecoder().decode(Report.self, from: Data(#"{"findings": []}"#.utf8))
        XCTAssertTrue(report.attackChains.isEmpty)
        XCTAssertNil(report.schemaVersion)
    }
}
