import XCTest
@testable import AttackMap

/// The "Suppress…" writer (#7): valid core syntax, existing content
/// preserved, and nothing written that core would skip. The live test
/// (`LiveEngineSurfaceTests`) parses the output with core's own parser and
/// confirms a rescan moves the finding to `suppressed_findings`.
final class SuppressFileWriterTests: XCTestCase {
    private var utc: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()

    private func date(_ y: Int, _ m: Int, _ d: Int) -> Date {
        utc.date(from: DateComponents(year: y, month: m, day: d, hour: 12))!
    }

    private let ruleEntry = SuppressRule(selector: .rule("hardcoded-secret"), reason: "fixtures only")

    func testCreatesCanonicalFileWhenMissing() throws {
        var rule = ruleEntry
        rule.paths = ["tests/fixtures/**", " ", "vendor/*"]
        rule.expires = date(2026, 12, 31)
        rule.owner = "platform-team"
        rule.ticket = "SEC-123"
        let text = try SuppressFileWriter.appending(rule, to: nil, calendar: utc)
        XCTAssertEqual(text, """
        version: 1
        suppress:
          - rule: "hardcoded-secret"
            reason: "fixtures only"
            paths: ["tests/fixtures/**", "vendor/*"]
            expires: 2026-12-31
            owner: "platform-team"
            ticket: "SEC-123"

        """)
    }

    func testIdEntryIsQuotedAndIgnoresPaths() throws {
        // A digit-only id would become a YAML int unquoted; core then skips it.
        var rule = SuppressRule(selector: .id("0123456789012345"), reason: "accepted risk")
        rule.paths = ["src/**"]
        let text = try SuppressFileWriter.appending(rule, to: nil, calendar: utc)
        XCTAssertTrue(text.contains(#"  - id: "0123456789012345""#), text)
        XCTAssertFalse(text.contains("paths"), "core would add a separate path suppression")
        XCTAssertFalse(text.contains("owner") || text.contains("ticket") || text.contains("expires"))
    }

    func testAppendsToExistingSuppressBlockPreservingContent() throws {
        let existing = """
        # Team suppressions — reviewed quarterly
        version: 1
        suppress:
            - id: "1a2b3c4d5e6f7a8b"   # JIRA-1
              reason: accepted risk

            # vendor code
            - path: "vendor/**"
              reason: third-party
        """
        let text = try SuppressFileWriter.appending(ruleEntry, to: existing, calendar: utc)
        XCTAssertTrue(text.hasPrefix(existing + "\n"), "existing bytes untouched")
        XCTAssertTrue(text.hasSuffix(
            "      reason: third-party\n    - rule: \"hardcoded-secret\"\n      reason: \"fixtures only\"\n"),
            "matches the file's 4-space list indent:\n\(text)")
    }

    func testInsertsBeforeAFollowingTopLevelKey() throws {
        let existing = """
        suppress:
        - rule: debug-enabled
          reason: local only

        # trailing settings
        version: 1

        """
        let text = try SuppressFileWriter.appending(ruleEntry, to: existing, calendar: utc)
        XCTAssertEqual(text, """
        suppress:
        - rule: debug-enabled
          reason: local only
        - rule: "hardcoded-secret"
          reason: "fixtures only"

        # trailing settings
        version: 1

        """)
    }

    func testEmptyFlowListIsConvertedToBlock() throws {
        let text = try SuppressFileWriter.appending(ruleEntry, to: "version: 1\nsuppress: []  # none yet\n", calendar: utc)
        XCTAssertEqual(text, "version: 1\nsuppress:\n  - rule: \"hardcoded-secret\"\n    reason: \"fixtures only\"\n")
    }

    func testNonEmptyFlowListIsRefused() {
        XCTAssertThrowsError(try SuppressFileWriter.appending(
            ruleEntry, to: "suppress: [{rule: x, reason: y}]\n", calendar: utc)) { error in
            guard case SuppressFileError.unsupportedLayout = error else { return XCTFail("\(error)") }
        }
    }

    func testMappingWithoutListGetsOneAndLegacyKeyIsReused() throws {
        XCTAssertEqual(try SuppressFileWriter.appending(ruleEntry, to: "version: 1", calendar: utc),
                       "version: 1\nsuppress:\n  - rule: \"hardcoded-secret\"\n    reason: \"fixtures only\"\n")
        let legacy = try SuppressFileWriter.appending(ruleEntry, to: "suppressions:\n  - rule: a\n    reason: b\n", calendar: utc)
        XCTAssertEqual(legacy, "suppressions:\n  - rule: a\n    reason: b\n  - rule: \"hardcoded-secret\"\n    reason: \"fixtures only\"\n")
    }

    func testTopLevelListAndCommentOnlyFiles() throws {
        XCTAssertEqual(try SuppressFileWriter.appending(ruleEntry, to: "- rule: a\n  reason: b\n", calendar: utc),
                       "- rule: a\n  reason: b\n- rule: \"hardcoded-secret\"\n  reason: \"fixtures only\"\n")
        XCTAssertEqual(try SuppressFileWriter.appending(ruleEntry, to: "# nothing yet", calendar: utc),
                       "# nothing yet\nversion: 1\nsuppress:\n  - rule: \"hardcoded-secret\"\n    reason: \"fixtures only\"\n")
    }

    func testCRLFLineEndingsArePreserved() throws {
        let text = try SuppressFileWriter.appending(ruleEntry, to: "version: 1\r\nsuppress:\r\n  - rule: a\r\n    reason: b\r\n", calendar: utc)
        XCTAssertEqual(text, "version: 1\r\nsuppress:\r\n  - rule: a\r\n    reason: b\r\n  - rule: \"hardcoded-secret\"\r\n    reason: \"fixtures only\"\r\n")
    }

    func testHostileReasonCannotBreakStructure() throws {
        let rule = SuppressRule(selector: .rule("x"), reason: "a: b # c\n- id: evil\n\"q\" \\ \t\u{1}\u{2028}end")
        let text = try SuppressFileWriter.appending(rule, to: nil, calendar: utc)
        XCTAssertEqual(text.split(separator: "\n").count, 4, text)
        XCTAssertTrue(text.contains(#"reason: "a: b # c\n- id: evil\n\"q\" \\ \t\x01\Lend""#), text)
    }

    func testValidationMirrorsCore() {
        XCTAssertThrowsError(try SuppressFileWriter.validate(SuppressRule(selector: .rule("x"), reason: "  \n")))
        XCTAssertThrowsError(try SuppressFileWriter.validate(SuppressRule(selector: .id("NOTHEX0000000000"), reason: "r")))
        XCTAssertThrowsError(try SuppressFileWriter.validate(SuppressRule(selector: .id("abc"), reason: "r")))
        XCTAssertThrowsError(try SuppressFileWriter.validate(SuppressRule(selector: .rule(" "), reason: "r")))
        for glob in ["*", "**", "**/*", "/", "./**"] {
            XCTAssertThrowsError(try SuppressFileWriter.validate(
                SuppressRule(selector: .rule("x"), reason: "r", paths: [glob])), glob)
        }
        XCTAssertNoThrow(try SuppressFileWriter.validate(
            SuppressRule(selector: .rule("x"), reason: "r", paths: ["tests/**", "*.py"])))
        XCTAssertNoThrow(try SuppressFileWriter.validate(SuppressRule(selector: .id("1a2b3c4d5e6f7a8b"), reason: "r")))
    }

    func testTargetPrefersOverrideThenExistingYmlThenNewYaml() throws {
        let repo = FileManager.default.temporaryDirectory.appendingPathComponent("sup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: repo) }
        XCTAssertEqual(SuppressFileWriter.targetURL(repoURL: repo).lastPathComponent, ".attackmap-suppress.yaml")
        try "".write(to: repo.appendingPathComponent(".attackmap-suppress.yml"), atomically: true, encoding: .utf8)
        XCTAssertEqual(SuppressFileWriter.targetURL(repoURL: repo).lastPathComponent, ".attackmap-suppress.yml")
        let custom = URL(fileURLWithPath: "/elsewhere/baseline.yaml")
        XCTAssertEqual(SuppressFileWriter.targetURL(repoURL: repo, override: custom), custom)
    }

    func testAppendWritesAndRereadsFromDisk() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sup-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent(".attackmap-suppress.yaml")
        try SuppressFileWriter.append(ruleEntry, to: file)
        try SuppressFileWriter.append(SuppressRule(selector: .rule("debug-enabled"), reason: "local"), to: file)
        let text = try String(contentsOf: file, encoding: .utf8)
        XCTAssertEqual(text.components(separatedBy: "suppress:").count, 2, "one list, two entries:\n\(text)")
        XCTAssertTrue(text.contains("- rule: \"hardcoded-secret\"") && text.contains("- rule: \"debug-enabled\""))
        XCTAssertThrowsError(try SuppressFileWriter.append(SuppressRule(selector: .rule("x"), reason: ""), to: file))
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), text, "a rejected entry writes nothing")
    }
}
