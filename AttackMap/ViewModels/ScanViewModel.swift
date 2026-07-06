import Foundation
import Observation

/// Drives a single scan: locates the CLI, spawns it, folds NDJSON progress
/// into observable state, and decodes the report on success.
@MainActor
@Observable
final class ScanViewModel {
    enum Phase: Equatable {
        case idle, scanning, done
        case failed(String)
    }

    // Inputs
    var repoURL: URL?
    var cliPathOverride: String = ""
    var runCVE: Bool = false
    var llmMode: ScanConfig.LLMMode = .none

    // Observable scan state
    private(set) var phase: Phase = .idle
    private(set) var statusLabel: String = ""
    private(set) var currentFile: String = ""
    private(set) var fraction: Double = 0
    private(set) var indeterminate: Bool = false
    private(set) var report: Report?

    private let runner = ProcessRunner()

    var isScanning: Bool { phase == .scanning }
    var canRun: Bool { repoURL != nil && !isScanning }

    func run() {
        guard let repoURL else { return }
        guard let cli = CLILocator.locate(explicitPath: cliPathOverride) else {
            phase = .failed(
                "attackmap not found. Install it (brew install mlaify/tap/attackmap) "
                + "or set its path in Settings.")
            return
        }

        let output = repoURL.appendingPathComponent(".attackmap-gui/reports", isDirectory: true)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        let config = ScanConfig(
            repoURL: repoURL,
            outputDirectory: output,
            runCVE: runCVE,
            llmMode: llmMode,
            baselineURL: nil)

        phase = .scanning
        report = nil
        fraction = 0
        indeterminate = false
        currentFile = ""
        statusLabel = "Starting…"

        Task {
            do {
                let result = try await runner.run(executable: cli, config: config) { [weak self] event in
                    Task { @MainActor in self?.apply(event) }
                }
                let decoded = try Report.load(from: result.reportURL)
                report = decoded
                phase = .done
                statusLabel = "Done — \(decoded.findings.count) finding"
                    + (decoded.findings.count == 1 ? "" : "s")
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                phase = .failed(message)
            }
        }
    }

    func cancel() {
        runner.cancel()
    }

    /// Fold one progress event into observable state. A scan emits several
    /// analyzer sub-passes, so each `begin` resets the determinate bar; overall
    /// completion is signaled by the process exiting, not by any single `done`.
    private func apply(_ event: ProgressEvent) {
        switch event.kind {
        case .begin:
            indeterminate = false
            fraction = 0
            statusLabel = event.label ?? "Scanning files"
        case .advance:
            indeterminate = false
            if let fraction = event.fraction { self.fraction = fraction }
            currentFile = event.current ?? ""
        case .stage:
            indeterminate = true
            statusLabel = event.label ?? "Analyzing"
            currentFile = ""
        case .done, .unknown:
            break
        }
    }
}
