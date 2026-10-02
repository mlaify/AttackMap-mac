import Foundation

/// Runs a short helper process (login-shell PATH lookup, `--help` probe,
/// `modules --json`) and captures its stdout.
///
/// - Reads stdout *while* the process runs, so output larger than the pipe
///   buffer (~64 KB) can't deadlock the child on write (#4).
/// - Gives up after `timeout`, terminating (then killing) the child, so a slow
///   or prompting `.zprofile` can't hang the app.
/// - Must not be called on the main thread (asserted in debug builds).
enum ShellRunner {
    struct Output {
        let status: Int32
        let stdout: Data
        var text: String { String(decoding: stdout, as: UTF8.self) }
    }

    static func run(_ executable: URL, _ arguments: [String],
                    environment: [String: String]? = nil,
                    timeout: TimeInterval) -> Output? {
        assert(!Thread.isMainThread, "ShellRunner.run spawns a process; call it off the main thread")
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        if let environment { process.environment = environment }
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            return nil
        }

        let collected = LockedData()
        let readerDone = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            collected.set(stdout.fileHandleForReading.readDataToEndOfFile())
            readerDone.signal()
        }

        if exited.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = exited.wait(timeout: .now() + 1)
            }
            return nil
        }
        // The reader hits EOF once every writer has closed; don't wait forever
        // if a grandchild inherited the pipe.
        _ = readerDone.wait(timeout: .now() + 1)
        return Output(status: process.terminationStatus, stdout: collected.get())
    }
}

private final class LockedData: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func set(_ value: Data) { lock.withLock { data = value } }
    func get() -> Data { lock.withLock { data } }
}
