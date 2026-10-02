import XCTest
@testable import AttackMap

/// Inventory sections of `scan` (#7): dependencies, vulnerabilities, secrets,
/// CI workflow issues, data flows, analyzer status. `live-report-inventory`
/// was produced by attackmap 0.5.0 (main, 2026-10-02) with `--format all`
/// and no `--cve` over a small Flask fixture with a requirements.txt and a
/// GitHub workflow; `sample-report-vulns` is hand-built to the core
/// `Vulnerability` / `AnalyzerError` models (a `--cve` run needs network).
final class InventoryDecodingTests: XCTestCase {
    private func url(_ name: String) throws -> URL {
        try XCTUnwrap(Bundle(for: Self.self).url(forResource: name, withExtension: "json"), "\(name).json missing")
    }

    private func rawScan(_ name: String) throws -> [String: Any] {
        let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: url(name))) as? [String: Any]
        return try XCTUnwrap(obj?["scan"] as? [String: Any])
    }

    private func decode(_ json: String) throws -> Report {
        try JSONDecoder().decode(Report.self, from: Data(json.utf8))
    }

    func testLiveInventoryDecodesEverySection() throws {
        let report = try Report.load(from: url("live-report-inventory"))
        let scan = try XCTUnwrap(report.scan)
        let raw = try rawScan("live-report-inventory")
        func rawCount(_ key: String) -> Int { (raw[key] as? [Any])?.count ?? -1 }

        // Counts match the raw JSON, so a renamed key can't silently empty a pane.
        XCTAssertEqual(scan.dependencies.count, rawCount("dependencies"))
        XCTAssertEqual(scan.dependencies.count, 3)
        XCTAssertEqual(scan.secrets.count, rawCount("secret_hints"))
        XCTAssertEqual(scan.workflowIssues.count, rawCount("workflow_issues"))
        XCTAssertGreaterThanOrEqual(scan.workflowIssues.count, 4)
        XCTAssertEqual(scan.taintChains.count, rawCount("taint_chains"))
        XCTAssertEqual(scan.vulnerabilities.count, 0, "no --cve in this run")
        XCTAssertEqual(scan.analyzerErrors.count, 0)

        let flask = try XCTUnwrap(scan.dependencies.first { $0.name == "flask" })
        XCTAssertEqual(flask.version, "==2.0.1")
        XCTAssertEqual(flask.ecosystem, "pypi")
        XCTAssertEqual(flask.file, "requirements.txt")
        XCTAssertEqual(flask.line, 1)
        XCTAssertTrue(flask.direct)
        XCTAssertFalse(flask.dev)

        let env = try XCTUnwrap(scan.secrets.first { $0.kind == "env_reference" })
        XCTAssertEqual(env.name, "DB_PASSWORD")
        XCTAssertFalse(env.isLiteral)
        let literal = try XCTUnwrap(scan.secrets.first { $0.isLiteral })
        XCTAssertEqual(literal.kind, "stripe_key")
        XCTAssertEqual(literal.file, "app.py")
        XCTAssertFalse(literal.name.contains("live"), "core redacts literal names")

        // Workflow kinds outside the documented Literal (e.g.
        // oidc_on_untrusted_trigger) must still decode.
        XCTAssertTrue(scan.workflowIssues.allSatisfy { $0.kind != "unknown" && !$0.file.isEmpty })
        XCTAssertTrue(scan.workflowIssues.contains { $0.kind == "unpinned_action" })
        XCTAssertTrue(scan.workflowIssues.contains { Severity($0.severity) == .high })

        let chain = try XCTUnwrap(scan.taintChains.first)
        XCTAssertEqual(chain.routePath, "/run")
        XCTAssertEqual(chain.sinkKind, "subprocess_shell")
        XCTAssertEqual(chain.sinkLine, 11)

        // Route auth (core #256) decodes; provenance is excluded by core today.
        XCTAssertEqual(scan.routes.count, 2)
        XCTAssertTrue(scan.routes.allSatisfy { ["required", "anonymous", "unknown"].contains($0.auth) })

        // Which analyzers ran comes from the review context pack.
        let pack = try XCTUnwrap((try JSONSerialization.jsonObject(with: Data(contentsOf: url("live-report-inventory"))) as? [String: Any])?["review_context_pack"] as? [String: Any])
        XCTAssertEqual(report.analyzersRun.count, (pack["analyzer_metadata_used"] as? [Any])?.count)
        XCTAssertTrue(report.analyzersRun.contains { $0.name == "python-web" })
    }

    func testLiveFindingsCarryRuleIdsAndLocations() throws {
        let report = try Report.load(from: url("live-report-inventory"))
        XCTAssertFalse(report.findings.isEmpty)
        for f in report.findings {
            XCTAssertNotNil(f.ruleId, f.title)
            XCTAssertEqual(f.id.count, 16)
        }
        let secret = try XCTUnwrap(report.findings.first { $0.ruleId == "hardcoded-secret" })
        XCTAssertEqual(secret.locationFiles, ["app.py"])
    }

    func testHandBuiltVulnerabilitiesAndAnalyzerErrors() throws {
        let report = try Report.load(from: url("sample-report-vulns"))
        let scan = try XCTUnwrap(report.scan)
        XCTAssertEqual(scan.vulnerabilities.count, 3)

        let yaml = try XCTUnwrap(scan.vulnerabilities.first { $0.packageName == "pyyaml" })
        XCTAssertEqual(yaml.advisoryId, "GHSA-6757-jp84-gxfx")
        XCTAssertEqual(yaml.cveAlias, "CVE-2020-1747")
        XCTAssertEqual(yaml.cvssScore, 9.8)
        XCTAssertEqual(Severity(yaml.severity), .high)
        XCTAssertEqual(yaml.affectedRange, "affected [0, 5.3.1)")
        XCTAssertEqual(yaml.references.count, 1)

        let qs = try XCTUnwrap(scan.vulnerabilities.first { $0.packageName == "qs" })
        XCTAssertFalse(qs.direct)
        XCTAssertEqual(qs.resolutionPath, "express > body-parser > qs")
        XCTAssertNil(qs.cvssScore)

        // Minimal entry with an ecosystem core doesn't (yet) emit: defaults.
        let mystery = try XCTUnwrap(scan.vulnerabilities.first { $0.packageName == "mystery" })
        XCTAssertEqual(mystery.ecosystem, "crates.io-future")
        XCTAssertEqual(mystery.severity, "medium")
        XCTAssertTrue(mystery.aliases.isEmpty)
        XCTAssertTrue(mystery.direct)

        let transitive = try XCTUnwrap(scan.dependencies.first { $0.name == "qs" })
        XCTAssertFalse(transitive.direct)
        XCTAssertTrue(transitive.resolved)
        XCTAssertEqual(transitive.via, "express > body-parser > qs")
        XCTAssertNil(transitive.line)
        XCTAssertTrue(try XCTUnwrap(scan.dependencies.first { $0.name == "jest" }).dev)

        XCTAssertEqual(scan.analyzerErrors.map(\.analyzer), ["acme-plugin", "partial-plugin"])
        XCTAssertEqual(scan.analyzerErrors[0].message, "boom")
        XCTAssertEqual(scan.analyzerErrors[1].message, "", "message is optional in core")
        XCTAssertEqual(scan.limitations.count, 1)

        // Provenance badges render when the engine includes source_analyzer.
        XCTAssertEqual(scan.routes.first?.sourceAnalyzer, "python-web")
        XCTAssertEqual(scan.routes.first?.auth, "required")
        XCTAssertEqual(scan.routes.first?.guards, ["@login_required"])
        XCTAssertEqual(scan.dependencies.first { $0.name == "pyyaml" }?.sourceAnalyzer, "config")
        XCTAssertEqual(report.analyzersRun.map(\.name), ["python-web", "config"])
        XCTAssertTrue(report.analyzersRun[1].ecosystems.isEmpty)
    }

    /// The secrets model has no field that could carry a value: evidence is
    /// never decoded, so the pane can't render it even by accident.
    func testSecretHintNeverDecodesEvidence() throws {
        let report = try Report.load(from: url("sample-report-vulns"))
        let secret = try XCTUnwrap(report.scan?.secrets.first)
        let labels = Mirror(reflecting: secret).children.compactMap(\.label)
        XCTAssertFalse(labels.contains { $0.lowercased().contains("evidence") }, "\(labels)")
        XCTAssertEqual(secret.name, "AWS_SECRET_ACCESS_KEY")
        XCTAssertTrue(secret.isLiteral)
    }

    /// Older CLIs omit every inventory key; a reshaped section degrades alone.
    func testOlderOrDriftedReportsStayTolerant() throws {
        let old = try decode(#"{"scan": {"root": "/r", "routes": [{"path": "/", "file": "a.py"}]}, "findings": [{"title": "T", "severity": "high"}]}"#)
        let scan = try XCTUnwrap(old.scan)
        XCTAssertTrue(scan.dependencies.isEmpty && scan.vulnerabilities.isEmpty && scan.secrets.isEmpty)
        XCTAssertTrue(scan.workflowIssues.isEmpty && scan.taintChains.isEmpty && scan.analyzerErrors.isEmpty)
        XCTAssertEqual(scan.routes.first?.auth, "unknown")
        XCTAssertNil(scan.routes.first?.sourceAnalyzer)
        XCTAssertTrue(old.analyzersRun.isEmpty)
        XCTAssertNil(old.findings.first?.ruleId)
        XCTAssertEqual(old.findings.first?.effectiveRuleId, "t")

        // `dependencies` reshaped to an object: only that section empties.
        let drifted = try decode(#"{"scan": {"root": "/r", "dependencies": {"pypi": []}, "secret_hints": [{"name": "K", "file": "f"}], "analyzer_errors": "oops"}, "review_context_pack": {"analyzer_metadata_used": 3}}"#)
        XCTAssertEqual(drifted.scan?.dependencies.count, 0)
        XCTAssertEqual(drifted.scan?.secrets.first?.kind, "env_reference")
        XCTAssertEqual(drifted.scan?.analyzerErrors.count, 0)
        XCTAssertTrue(drifted.analyzersRun.isEmpty)
    }

    /// The pre-0.5 live fixtures still decode, with their inventory where present.
    func testEarlierLiveFixtureStillDecodes() throws {
        let report = try Report.load(from: url("live-report"))
        XCTAssertEqual(report.findings.count, 9)
        XCTAssertNotNil(report.scan)
    }

    func testTitleSlugMatchesCore() {
        // core models.title_slug: re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        XCTAssertEqual(Finding.titleSlug("Hard-coded secret literals were found"), "hard-coded-secret-literals-were-found")
        XCTAssertEqual(Finding.titleSlug("  CSRF: off!! "), "csrf-off")
        XCTAssertEqual(Finding.titleSlug("§§§"), "finding")
        XCTAssertEqual(Finding.titleSlug("Request-reachable OS command (exec)"), "request-reachable-os-command-exec")
    }
}
