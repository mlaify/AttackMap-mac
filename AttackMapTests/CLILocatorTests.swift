import XCTest
@testable import AttackMap

/// ShellRunner / CLILocator: no hangs, no pipe deadlock, structured
/// capability detection with help-text fallback (#4).
final class CLILocatorTests: XCTestCase {
    private var work: URL!

    override func setUpWithError() throws {
        work = FileManager.default.temporaryDirectory.appendingPathComponent("cli-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: work) }

    private func script(_ body: String) throws -> URL {
        let url = work.appendingPathComponent("s-\(UUID().uuidString)")
        try "#!/bin/sh\n\(body)\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    private func offMain<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await Task.detached { body() }.value
    }

    func testTimeoutKillsAHangingCommand() async throws {
        let exe = try script("sleep 30")
        let start = Date()
        let out = await offMain { ShellRunner.run(exe, [], timeout: 0.5) }
        XCTAssertNil(out)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testLargeOutputDoesNotDeadlock() async throws {
        let exe = try script("head -c 200000 /dev/zero | tr '\\\\0' 'a'")
        let out = await offMain { ShellRunner.run(exe, [], timeout: 10) }
        XCTAssertEqual(out?.status, 0)
        XCTAssertEqual(out?.stdout.count, 200_000)
    }

    func testPrefersStructuredCapabilities() async throws {
        let exe = try script("""
        if [ "$1" = capabilities ]; then
          echo '{"schema": 1, "version": "9.9", "commands": ["analyze"], "analyze": {"options": ["--recall", "--progress-format"], "multi_repo": true}, "progress_protocol": 1}'
        else
          echo "--llm-speed --triage fleet"
        fi
        """)
        let caps = await offMain { CLILocator.capabilities(executable: exe) }
        XCTAssertTrue(caps.recall)
        XCTAssertTrue(caps.progressJSON)
        XCTAssertTrue(caps.fleet)
        XCTAssertFalse(caps.llmSpeed, "help text must not be consulted when JSON is available")
        XCTAssertFalse(caps.triage)
    }

    func testFallsBackToHelpForOlderCLIs() async throws {
        let exe = try script("""
        if [ "$1" = capabilities ]; then echo "No such command" >&2; exit 2; fi
        echo "--progress-format --triage"
        """)
        let caps = await offMain { CLILocator.capabilities(executable: exe) }
        XCTAssertTrue(caps.progressJSON)
        XCTAssertTrue(caps.triage)
        XCTAssertFalse(caps.recall)
    }

    func testCachedLocateNeverSpawnsAndHonorsExplicitPath() throws {
        let exe = try script("exit 0")
        XCTAssertEqual(CLILocator.cachedLocate(explicitPath: exe.path), exe)
        XCTAssertNil(CLILocator.cachedLocate(explicitPath: work.appendingPathComponent("missing").path))
    }
}
