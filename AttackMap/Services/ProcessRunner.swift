import Foundation

/// Outcome of a completed scan.
struct ScanRunResult {
    let exitCode: Int32
    let reportURL: URL
    let stdout: String
    let stderrTail: String
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

/// Keeps the last N non-progress stderr lines (e.g. "LLM review skipped: …"),
/// so a silent backend failure can be surfaced to the user.
private final class StderrTail {
    private var lines: [String] = []
    private let limit = 50

    func append(_ line: String) {
        lines.append(line)
        if lines.count > limit { lines.removeFirst(lines.count - limit) }
    }

    var text: String { lines.joined(separator: "\n") }
}

/// Spawns `attackmap analyze …`, streams NDJSON progress from stderr, and
/// resolves with the report location on success. Not tied to any UI type; the
/// caller hops `onProgress` to the main actor as needed.
final class ProcessRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?

    /// Run a single-repo scan to completion. `onProgress` fires for each decoded
    /// progress event (on an arbitrary queue — marshal to the main actor).
    func run(executable: URL,
             config: ScanConfig,
             progressJSON: Bool,
             environment extraEnvironment: [String: String] = [:],
             onProgress: @escaping @Sendable (ProgressEvent) -> Void) async throws -> ScanRunResult {
        try await run(
            executable: executable,
            arguments: config.arguments(progressJSON: progressJSON),
            currentDirectory: config.repoURL,
            successFile: config.reportURL,
            environment: extraEnvironment,
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
    private func run(executable: URL,
                     arguments: [String],
                     currentDirectory: URL?,
                     successFile: URL,
                     environment extraEnvironment: [String: String],
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
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            for line in buffer.take(data) {
                if let event = ProgressEvent.decode(line: line) {
                    onProgress(event)
                } else {
                    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty { stderrTail.append(trimmed) }
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

        // Drain stdout on a background thread *while the scan runs*. If we waited
        // until after exit to read it (as this once did), a large report on
        // stdout would fill the ~64KB pipe buffer, block the CLI's write, and
        // stop it from ever exiting — the scan would hang at 100%.
        let stdoutHandle = stdoutPipe.fileHandleForReading
        async let stdoutText: String = Task.detached {
            String(decoding: stdoutHandle.readDataToEndOfFile(), as: UTF8.self)
        }.value

        // Await termination without blocking a thread.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            process.terminationHandler = { _ in continuation.resume() }
        }

        let stdout = await stdoutText
        let code = process.terminationStatus

        // SIGTERM from cancel() surfaces as a signal termination (negative/15).
        if process.terminationReason == .uncaughtSignal {
            throw ScanRunError.cancelled
        }
        guard code == 0 else {
            throw ScanRunError.nonZeroExit(code: code, stdout: stdout)
        }
        guard FileManager.default.fileExists(atPath: successFile.path) else {
            throw ScanRunError.reportMissing(successFile)
        }
        return ScanRunResult(
            exitCode: code, reportURL: successFile,
            stdout: stdout, stderrTail: stderrTail.text)
    }

    /// Terminate the in-flight scan, if any.
    func cancel() {
        lock.withLock { process?.terminate() }
    }
}
