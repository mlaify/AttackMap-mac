import XCTest
@testable import AttackMap

/// Lifecycle tests for ProcessRunner (#3), driven with small shell scripts.
final class ProcessRunnerTests: XCTestCase {
    private var work: URL!

    override func setUpWithError() throws {
        work = FileManager.default.temporaryDirectory
            .appendingPathComponent("processrunner-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: work)
    }

    private func script(_ body: String) throws -> URL {
        let url = work.appendingPathComponent("s-\(UUID().uuidString).sh")
        try "#!/bin/sh\n\(body)\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    private func run(_ runner: ProcessRunner, _ executable: URL,
                     onProgress: @escaping @Sendable (ProgressEvent) -> Void = { _ in }) async throws -> ScanRunResult {
        try await runner.run(executable: executable, arguments: [], currentDirectory: work,
                             successFile: work.appendingPathComponent("never"),
                             environment: [:], onProgress: onProgress)
    }

    func testInstantExitDoesNotHang() async throws {
        let start = Date()
        do {
            _ = try await run(ProcessRunner(), URL(fileURLWithPath: "/usr/bin/false"))
            XCTFail("expected nonZeroExit")
        } catch ScanRunError.nonZeroExit(let code, _, _) {
            XCTAssertEqual(code, 1)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testFinalStderrLineWithoutNewlineIsKept() async throws {
        let exe = try script(#"printf 'Traceback\nValueError: boom' >&2; exit 3"#)
        do {
            _ = try await run(ProcessRunner(), exe)
            XCTFail("expected nonZeroExit")
        } catch ScanRunError.nonZeroExit(let code, _, let tail) {
            XCTAssertEqual(code, 3)
            XCTAssertTrue(tail.hasSuffix("ValueError: boom"), tail)
        }
    }

    func testSplitMultibyteCharacterDecodes() {
        let buffer = LineBuffer()
        let bytes = Array("café\n".utf8)          // é = 0xC3 0xA9
        let split = bytes.firstIndex(of: 0xC3)! + 1
        XCTAssertEqual(buffer.take(Data(bytes[..<split])), [])
        XCTAssertEqual(buffer.take(Data(bytes[split...])), ["café"])
        XCTAssertNil(buffer.flush())
    }

    func testProgressEventsStillStream() async throws {
        let exe = try script(#"echo '{"v":1,"event":"begin","total":2}' >&2; echo '{"v":1,"event":"done"}' >&2; exit 1"#)
        let kinds = Kinds()
        _ = try? await run(ProcessRunner(), exe) { kinds.append($0.kind) }
        XCTAssertEqual(kinds.all, [.begin, .done])
    }

    func testCancelKillsGrandchild() async throws {
        let pidFile = work.appendingPathComponent("child.pid")
        let exe = try script("sh -c 'sleep 60' &\necho $! > '\(pidFile.path)'\nwait")
        let runner = ProcessRunner(killGracePeriod: 0.5)
        let cwd: URL = work
        let task = Task {
            try await runner.run(executable: exe, arguments: [], currentDirectory: cwd,
                                 successFile: cwd.appendingPathComponent("never"),
                                 environment: [:], onProgress: { _ in })
        }
        let childPID = try await waitForPID(at: pidFile)
        runner.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch ScanRunError.cancelled {}
        try await Task.sleep(nanoseconds: 1_500_000_000)
        XCTAssertNotEqual(kill(childPID, 0), 0, "grandchild \(childPID) survived cancel")
    }

    func testExternalSigkillIsCrashNotCancel() async throws {
        let exe = try script("kill -KILL $$")
        do {
            _ = try await run(ProcessRunner(), exe)
            XCTFail("expected crashed")
        } catch ScanRunError.crashed(let signal, _) {
            XCTAssertEqual(signal, SIGKILL)
        }
    }

    private func waitForPID(at url: URL) async throws -> pid_t {
        for _ in 0..<100 {
            if let text = try? String(contentsOf: url, encoding: .utf8),
               let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
                return pid
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw XCTSkip("child never started")
    }
}

private final class Kinds: @unchecked Sendable {
    private let lock = NSLock()
    private var kinds: [ProgressEvent.Kind] = []
    func append(_ kind: ProgressEvent.Kind) { lock.withLock { kinds.append(kind) } }
    var all: [ProgressEvent.Kind] { lock.withLock { kinds } }
}
