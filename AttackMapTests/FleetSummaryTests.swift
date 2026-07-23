import XCTest
@testable import AttackMap

/// Decodes a representative `fleet-summary.json` to lock the fleet Codable
/// models against the engine's output shape (#146).
final class FleetSummaryTests: XCTestCase {
    private func fixtureURL() throws -> URL {
        let url = Bundle(for: Self.self).url(forResource: "sample-fleet-summary", withExtension: "json")
        return try XCTUnwrap(url, "sample-fleet-summary.json missing from the test bundle")
    }

    func testDecodesRealFleetSummary() throws {
        let fleet = try FleetSummary.load(from: fixtureURL())
        XCTAssertEqual(fleet.repoCount, 3)
        XCTAssertEqual(fleet.totalFindings, 12)
        XCTAssertEqual(fleet.repos.count, 3)
        XCTAssertEqual(fleet.crossRepoLinks.count, 1)
        XCTAssertEqual(fleet.crossBoundaryFlows.count, 1)
        XCTAssertEqual(fleet.trustGaps.count, 1)
        XCTAssertEqual(fleet.crossRepoAnomalies.count, 1)
        XCTAssertEqual(fleet.crossRepoSignalCount, 3)
    }

    func testRepoSeverityCounts() throws {
        let fleet = try FleetSummary.load(from: fixtureURL())
        let gateway = try XCTUnwrap(fleet.repos.first { $0.repoId == "api-gateway" })
        XCTAssertEqual(gateway.count(.high), 2)
        XCTAssertEqual(gateway.count(.medium), 2)
        XCTAssertEqual(gateway.count(.critical), 0)  // absent → 0
        XCTAssertEqual(gateway.suppressed, 1)
    }

    func testCrossBoundaryFieldsAndSeverityRank() throws {
        let fleet = try FleetSummary.load(from: fixtureURL())
        let flow = try XCTUnwrap(fleet.crossBoundaryFlows.first)
        XCTAssertEqual(flow.clientRepo, "api-gateway")
        XCTAssertEqual(flow.serverRepo, "user-service")
        XCTAssertEqual(flow.basis, "taint")
        XCTAssertEqual(Severity(flow.severity), .high)
        XCTAssertEqual(flow.serverLocation, "app/routes/users.py:44")
    }

    func testAnomalyPeers() throws {
        let fleet = try FleetSummary.load(from: fixtureURL())
        let anomaly = try XCTUnwrap(fleet.crossRepoAnomalies.first)
        XCTAssertEqual(anomaly.repo, "billing-service")
        XCTAssertEqual(anomaly.peers, ["user-service", "api-gateway"])
    }

    func testTolerantDecodeOfEmptyFleet() throws {
        let fleet = try JSONDecoder().decode(FleetSummary.self, from: Data("{}".utf8))
        XCTAssertEqual(fleet.repoCount, 0)
        XCTAssertTrue(fleet.repos.isEmpty)
        XCTAssertEqual(fleet.crossRepoSignalCount, 0)
    }
}
