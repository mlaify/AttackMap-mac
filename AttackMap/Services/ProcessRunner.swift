import Foundation
import Synchronization

/// Outcome of a completed scan.
struct ScanRunResult {
    let exitCode: Int32
    let reportURL: URL
    let stdout: String
    let stderrTail: String

    /// The run exited 1 because `--fail-on-new-high` tripped (reports were
    /// still written).
    var newHighGateFailed: Bool {
        exitCode == 1 && Self.isNewHighGateFailure(stderrTail: stderrTail)
    }

    static func isNewHighGateFailure(stderrTail: String) -> Bool {
        stderrTail.contains("failing per --fail-on-new-high")
    }
}

enum ScanRunError: Error, LocalizedError {
    case launchFailed(String)
    case nonZeroExit(code: Int32, stdout: String, stderrTail: String)
    case reportMissing(URL)
    case cancelled
    /// The CLI was killed by a signal the app didn't send (crash, OOM killer).
    case crashed(signal: Int32, stderrTail: String)

    var errorDescription: String? {
        switch self {
        case .launchFailed(let why): return "Couldn't launch attackmap: \(why)"
        case .nonZeroExit(let code, _, _): return "attackmap exited with code \(code)."
        case .reportMissing(let url): return "Scan finished but no report at \(url.path)."
        case .cancelled: return "Scan cancelled."
        case .crashed(let signal, _):
            return "attackmap was terminated by signal \(signal) (\(ProcessRunner.signalName(signal)))."
        }
    }

    /// Extra diagnostic detail (e.g. the CLI's stderr tail) to show beneath the
    /// summary message, when available.
    var detail: String? {
        switch self {
        case .nonZeroExit(_, let stdout, let stderrTail):
            let combined = [stderrTail, stdout]
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: "\n")
            return combined.isEmpty ? nil : combined
        case .crashed(_, let stderrTail):
            let tail = stderrTail.trimmingCharacters(in: .whitespacesAndNewlines)
            return tail.isEmpty ? nil : tail
        default:
            return nil
        }
    }
}

/// Accumulates streamed bytes and yields complete lines as they arrive.
///
/// Splits raw bytes on `\n` *before* decoding, so a multi-byte UTF-8 character
/// split across two reads (e.g. `é` in a repo path) decodes intact. Thread-safe:
/// the pipe's readability handler and the post-exit drain can both feed it.
final class LineBuffer: Sendable {
    private let partialData = Mutex(Data())

    func take(_ data: Data) -> [String] {
        partialData.withLock { partial in
            partial.append(data)
            var lines: [String] = []
            while let newline = partial.firstIndex(of: 0x0A) {
                lines.append(String(decoding: partial[partial.startIndex..<newline], as: UTF8.self))
                partial.removeSubrange(partial.startIndex...newline)
            }
            return lines
        }
    }

    /// The trailing line that had no newline, if any (call once, after EOF).
    func flush() -> String? {
        partialData.withLock { partial in
            guard !partial.isEmpty else { return nil }
            defer { partial.removeAll() }
            return String(decoding: partial, as: UTF8.self)
        }
    }
}

/// Keeps the last N non-progress stderr lines (e.g. "LLM review skipped: …"),
/// so a silent backend failure can be surfaced to the user.
final class StderrTail: Sendable {
    private let lines = Mutex<[String]>([])
    private let limit = 50

    func append(_ line: String) {
        lines.withLock { lines in
            lines.append(line)
            if lines.count > limit { lines.removeFirst(lines.count - limit) }
        }
    }

    var text: String { lines.withLock { $0.joined(separator: "\n") } }
}

/// Resumes a waiter exactly once, whether the event fires before or after the
/// wait starts. The termination handler is installed *before* `run()` (a CLI
/// that fails instantly can exit before a later assignment), so it may fire
/// before anyone awaits it.
final class OneShotSignal: Sendable {
    private struct State {
        var fired = false
        var continuation: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())

    func fire() {
        let waiter: CheckedContinuation<Void, Never>? = state.withLock { state in
            guard !state.fired else { return nil }
            state.fired = true
            defer { state.continuation = nil }
            return state.continuation
        }
        waiter?.resume()
    }

    func wait() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = state.withLock { state in
                if state.fired { return true }
                state.continuation = c
                return false
            }
            if resumeNow { c.resume() }
        }
    }
}

/// Spawns `attackmap analyze …`, streams NDJSON progress from stderr, and
/// resolves with the report location on success. Not tied to any UI type; the
/// caller hops `onProgress` to the main actor as needed.
///
/// `@unchecked Sendable`: `process` and `cancelRequested` are only touched
/// under `lock`. (`Process` isn't Sendable, so it can't live in a `Mutex`.)
final class ProcessRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelRequested = false

    /// How long `cancel()` waits after SIGTERM before SIGKILLing what's left.
    let killGracePeriod: TimeInterval

    init(killGracePeriod: TimeInterval = 3) {
        self.killGracePeriod = killGracePeriod
    }

    /// Run a single-repo scan to completion. `onProgress` fires for each decoded
    /// progress event (on an arbitrary queue — marshal to the main actor).
    func run(executable: URL,
             config: ScanConfig,
             progressJSON: Bool,
             environment extraEnvironment: [String: String] = [:],
             onProgress: @escaping @Sendable (ProgressEvent) -> Void) async throws -> ScanRunResult {
        // `--fail-on-new-high` exits 1 *after* writing every report when the
        // diff introduces new HIGH findings. That's a gate result, not a
        // failed scan: accept it (the caller surfaces it) when the engine says
        // so on stderr.
        let gate = config.baselineURL != nil && config.failOnNewHigh
        return try await run(
            executable: executable,
            arguments: config.arguments(progressJSON: progressJSON),
            currentDirectory: config.repoURL,
            successFile: config.reportURL,
            environment: extraEnvironment,
            tolerateExit: { code, stderr in
                gate && code == 1 && ScanRunResult.isNewHighGateFailure(stderrTail: stderr)
            },
            onProgress: onProgress)
    }

    /// Run a multi-repo fleet scan to completion. Succeeds when the engine has
    /// written `fleet-summary.json` into the fleet output directory.
    func runFleet(executable: URL,
                  config: ScanConfig,
                  paths: [URL],
                  progressJSON: Bool,
                  environment extraEnvironment: [String: String] = [:],
                  onProgress: @escaping @Sendable (ProgressEvent) -> Void) async throws -> ScanRunResult {
        try await run(
            executable: executable,
            arguments: config.fleetArguments(paths: paths, progressJSON: progressJSON),
            currentDirectory: paths.first,
            successFile: config.outputDirectory.appendingPathComponent("fleet-summary.json"),
            environment: extraEnvironment,
            onProgress: onProgress)
    }

    /// Core runner: spawn `attackmap` with an explicit argument vector, stream
    /// NDJSON progress, and resolve when `successFile` exists after a clean exit.
    /// Internal (not private) so the lifecycle can be unit-tested with any
    /// executable.
    func run(executable: URL,
                     arguments: [String],
                     currentDirectory: URL?,
                     successFile: URL,
                     environment extraEnvironment: [String: String],
                     tolerateExit: @Sendable (Int32, String) -> Bool = { _, _ in false },
                     onProgress: @escaping @Sendable (ProgressEvent) -> Void) async throws -> ScanRunResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory

        // Start from the app env, widen PATH to the login shell's (so tools the
        // CLI shells out to — e.g. the `claude` backend — resolve), then apply
        // caller overrides (API key).
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = LoginShellEnvironment.mergedPath(with: environment["PATH"])
        environment.merge(extraEnvironment) { _, new in new }
        process.environment = environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let buffer = LineBuffer()
        let stderrTail = StderrTail()
        let handleLine: @Sendable (String) -> Void = { line in
            if let event = ProgressEvent.decode(line: line) {
                onProgress(event)
            } else {
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { stderrTail.append(trimmed) }
            }
        }
        let stderrHandle = stderrPipe.fileHandleForReading
        // Held while a handler invocation runs, so after clearing the handler
        // we can wait out one that's mid-flight — otherwise its lines (e.g.
        // the --fail-on-new-high message) could land after we read the tail.
        let handlerLock = NSLock()
        stderrHandle.readabilityHandler = { handle in
            handlerLock.withLock {
                let data = handle.availableData
                guard !data.isEmpty else { return }
                buffer.take(data).forEach(handleLine)
            }
        }

        // Installed before run(): a CLI that exits immediately (usage error,
        // missing interpreter) must still resume the wait below.
        let terminated = OneShotSignal()
        process.terminationHandler = { _ in terminated.fire() }

        lock.withLock {
            self.process = process
            self.cancelRequested = false
        }
        defer {
            stderrHandle.readabilityHandler = nil
            lock.withLock { self.process = nil }
        }

        do {
            try process.run()
        } catch {
            throw ScanRunError.launchFailed(String(describing: error))
        }

        // Drain stdout on a background thread *while the scan runs*. If we waited
        // until after exit to read it (as this once did), a large report on
        // stdout would fill the ~64KB pipe buffer, block the CLI's write, and
        // stop it from ever exiting — the scan would hang at 100%.
        let stdoutHandle = stdoutPipe.fileHandleForReading
        async let stdoutText: String = Task.detached {
            String(decoding: stdoutHandle.readDataToEndOfFile(), as: UTF8.self)
        }.value

        // Await termination without blocking a thread.
        await terminated.wait()

        // Whatever stderr is still buffered (often the last lines of a Python
        // traceback) plus the final line if it had no trailing newline.
        stderrHandle.readabilityHandler = nil
        handlerLock.withLock {}
        Self.drainNonBlocking(stderrHandle).map { buffer.take($0).forEach(handleLine) }
        buffer.flush().map(handleLine)

        let stdout = await stdoutText
        let code = process.terminationStatus

        if process.terminationReason == .uncaughtSignal {
            if lock.withLock({ cancelRequested }) {
                throw ScanRunError.cancelled
            }
            throw ScanRunError.crashed(signal: code, stderrTail: stderrTail.text)
        }
        guard code == 0 || tolerateExit(code, stderrTail.text) else {
            throw ScanRunError.nonZeroExit(code: code, stdout: stdout, stderrTail: stderrTail.text)
        }
        guard FileManager.default.fileExists(atPath: successFile.path) else {
            throw ScanRunError.reportMissing(successFile)
        }
        return ScanRunResult(
            exitCode: code, reportURL: successFile,
            stdout: stdout, stderrTail: stderrTail.text)
    }

    /// Terminate the in-flight scan and everything it spawned (LLM backends,
    /// `pip install` from module auto-install): SIGTERM the whole process tree,
    /// then SIGKILL whatever is still alive after `killGracePeriod`.
    func cancel() {
        let target: Process? = lock.withLock {
            guard let process, process.isRunning else { return nil }
            cancelRequested = true
            return process
        }
        guard let target else { return }
        let root = target.processIdentifier
        // Collect descendants *before* signalling: once the CLI dies its
        // children are reparented to launchd and can no longer be found.
        let tree = ProcessTree.descendants(of: root) + [root]
        for pid in tree { kill(pid, SIGTERM) }
        let grace = killGracePeriod
        DispatchQueue.global().asyncAfter(deadline: .now() + grace) {
            for pid in tree + ProcessTree.descendants(of: root) where kill(pid, 0) == 0 {
                kill(pid, SIGKILL)
            }
        }
    }

    /// Read whatever is buffered on `handle` without waiting for EOF (a
    /// grandchild that inherited the pipe could keep it open indefinitely).
    static func drainNonBlocking(_ handle: FileHandle) -> Data? {
        let fd = handle.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return nil }
        var data = Data()
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n > 0 { data.append(chunk, count: n) } else { break }
        }
        return data.isEmpty ? nil : data
    }

    static func signalName(_ signal: Int32) -> String {
        switch signal {
        case SIGKILL: return "SIGKILL — killed, possibly out of memory"
        case SIGSEGV: return "SIGSEGV — crashed"
        case SIGABRT: return "SIGABRT — aborted"
        case SIGBUS: return "SIGBUS — crashed"
        case SIGTERM: return "SIGTERM"
        case SIGINT: return "SIGINT"
        default: return "signal \(signal)"
        }
    }
}

/// Finds a process's descendants (children, grandchildren, …) via libproc.
enum ProcessTree {
    static func descendants(of pid: pid_t) -> [pid_t] {
        var result: [pid_t] = []
        var queue: [pid_t] = [pid]
        while let parent = queue.popLast() {
            for child in children(of: parent) where !result.contains(child) {
                result.append(child)
                queue.append(child)
            }
        }
        return result
    }

    private static func children(of pid: pid_t) -> [pid_t] {
        let estimate = proc_listchildpids(pid, nil, 0)
        guard estimate > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(estimate) + 16)
        let count = pids.withUnsafeMutableBytes { buf in
            proc_listchildpids(pid, buf.baseAddress, Int32(buf.count))
        }
        guard count > 0 else { return [] }
        return Array(pids.prefix(Int(count))).filter { $0 > 0 }
    }
}
