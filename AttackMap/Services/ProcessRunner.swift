import Foundation

/// Outcome of a completed scan.
struct ScanRunResult {
    let exitCode: Int32
    let reportURL: URL
    let stdout: String
}

enum ScanRunError: Error, LocalizedError {
    case launchFailed(String)
    case nonZeroExit(code: Int32, stdout: String)
    case reportMissing(URL)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .launchFailed(let why): return "Couldn't launch attackmap: \(why)"
        case .nonZeroExit(let code, _): return "attackmap exited with code \(code)."
        case .reportMissing(let url): return "Scan finished but no report at \(url.path)."
        case .cancelled: return "Scan cancelled."
        }
    }
}

/// Accumulates streamed bytes and yields complete lines as they arrive.
private final class LineBuffer {
    private var partial = ""

    func take(_ data: Data) -> [String] {
        partial += String(decoding: data, as: UTF8.self)
        var lines: [String] = []
        while let newline = partial.firstIndex(of: "\n") {
            lines.append(String(partial[..<newline]))
            partial = String(partial[partial.index(after: newline)...])
        }
        return lines
    }
}

/// Spawns `attackmap analyze …`, streams NDJSON progress from stderr, and
/// resolves with the report location on success. Not tied to any UI type; the
/// caller hops `onProgress` to the main actor as needed.
final class ProcessRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?

    /// Run a scan to completion. `onProgress` fires for each decoded progress
    /// event (on an arbitrary queue — marshal to the main actor in the closure).
    func run(executable: URL,
             config: ScanConfig,
             progressJSON: Bool,
             onProgress: @escaping @Sendable (ProgressEvent) -> Void) async throws -> ScanRunResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = config.arguments(progressJSON: progressJSON)
        process.currentDirectoryURL = config.repoURL
        process.environment = ProcessInfo.processInfo.environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let buffer = LineBuffer()
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            for line in buffer.take(data) {
                if let event = ProgressEvent.decode(line: line) {
                    onProgress(event)
                }
            }
        }

        lock.withLock { self.process = process }
        defer {
            stderrPipe.fileHandleForReading.readabilityHandler = nil
            lock.withLock { self.process = nil }
        }

        do {
            try process.run()
        } catch {
            throw ScanRunError.launchFailed(String(describing: error))
        }

        // Await termination without blocking a thread.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            process.terminationHandler = { _ in continuation.resume() }
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(decoding: stdoutData, as: UTF8.self)
        let code = process.terminationStatus

        // SIGTERM from cancel() surfaces as a signal termination (negative/15).
        if process.terminationReason == .uncaughtSignal {
            throw ScanRunError.cancelled
        }
        guard code == 0 else {
            throw ScanRunError.nonZeroExit(code: code, stdout: stdout)
        }
        guard FileManager.default.fileExists(atPath: config.reportURL.path) else {
            throw ScanRunError.reportMissing(config.reportURL)
        }
        return ScanRunResult(exitCode: code, reportURL: config.reportURL, stdout: stdout)
    }

    /// Terminate the in-flight scan, if any.
    func cancel() {
        lock.withLock { process?.terminate() }
    }
}
