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
    var model: ScanConfig.LLMModel = .opus48
    var effort: ScanConfig.Effort = .high
    var fast: Bool = false

    // Observable scan state
    private(set) var phase: Phase = .idle
    private(set) var statusLabel: String = ""
    private(set) var currentFile: String = ""
    private(set) var fraction: Double = 0
    private(set) var indeterminate: Bool = false
    private(set) var etaText: String = ""
    /// Live elapsed time in the current indeterminate phase (e.g. an LLM call),
    /// so a long "thinking" step always shows a moving timer.
    private(set) var stageElapsedText: String = ""
    private(set) var report: Report?
    /// Directory the last successful scan wrote its artifacts to (for diagrams).
    private(set) var outputDirectory: URL?
    /// New / resolved finding counts vs. the immediately prior scan of this repo.
    private(set) var lastDelta: (added: Int, resolved: Int)?
    /// Whether watch mode is auto-rescanning on file changes.
    private(set) var watchEnabled = false
    /// Non-fatal warning surfaced after a scan (e.g. an LLM mode that produced
    /// no output because no backend was available).
    private(set) var warning: String?

    private let runner = ProcessRunner()
    private let watcher = RepoWatcher()
    private var startedAt: Date?
    private var rescanPending = false
    private var stageStartedAt: Date?
    private var stageTimerTask: Task<Void, Never>?

    var isScanning: Bool { phase == .scanning }
    var canRun: Bool { repoURL != nil && !isScanning }

    func run() {
        guard let repoURL else { return }
        // Honor an explicit CLI path from Settings (shared via UserDefaults).
        let override = UserDefaults.standard.string(forKey: "cliPathOverride") ?? cliPathOverride
        guard let cli = CLILocator.locate(explicitPath: override) else {
            phase = .failed(
                "attackmap not found. Install it (brew install mlaify/tap/attackmap) "
                + "or set its path in Settings.")
            return
        }

        // Provide the API key only when an LLM mode actually needs it.
        var environment: [String: String] = [:]
        if llmMode != .none, let key = Keychain.get(account: Keychain.anthropicAPIKey), !key.isEmpty {
            environment["ANTHROPIC_API_KEY"] = key
        }

        // Capture the prior scan's finding IDs so we can report new/resolved.
        let hadPrevious = report != nil
        let previousIDs = Set(report?.findings.map(\.id) ?? [])

        let output = repoURL.appendingPathComponent(".attackmap-gui/reports", isDirectory: true)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        var config = ScanConfig(
            repoURL: repoURL,
            outputDirectory: output,
            runCVE: runCVE,
            llmMode: llmMode,
            model: model,
            effort: effort,
            fast: fast,
            baselineURL: nil)

        phase = .scanning
        report = nil
        fraction = 0
        indeterminate = false
        currentFile = ""
        etaText = ""
        warning = nil
        stopStageTimer()
        statusLabel = "Starting…"
        startedAt = Date()

        Task {
            // Older CLIs don't know newer flags; feature-detect off the main
            // actor and adapt so we never pass an unknown option (exit 2).
            let caps = await Task.detached {
                CLILocator.capabilities(executable: cli)
            }.value
            let progressJSON = caps.progressJSON
            if !progressJSON {
                indeterminate = true
                statusLabel = "Scanning… (update attackmap for live progress)"
            }
            // Fast mode needs the --llm-speed flag; drop it on older CLIs.
            if config.fast && !caps.llmSpeed {
                config.fast = false
            }
            do {
                let result = try await runner.run(
                    executable: cli, config: config,
                    progressJSON: progressJSON, environment: environment
                ) { [weak self] event in
                    Task { @MainActor in self?.apply(event) }
                }
                let decoded = try Report.load(from: result.reportURL)
                if hadPrevious {
                    let newIDs = Set(decoded.findings.map(\.id))
                    lastDelta = (added: newIDs.subtracting(previousIDs).count,
                                 resolved: previousIDs.subtracting(newIDs).count)
                } else {
                    lastDelta = nil
                }
                report = decoded
                outputDirectory = config.outputDirectory
                RecentScansStore.record(repoURL, at: Date())
                warning = llmOutputWarning(config: config, stderrTail: result.stderrTail)
                phase = .done
                statusLabel = "Done — \(decoded.findings.count) finding"
                    + (decoded.findings.count == 1 ? "" : "s")
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                phase = .failed(message)
            }
            stopStageTimer()
            // A file change during the scan queues exactly one follow-up run.
            if rescanPending, watchEnabled {
                rescanPending = false
                run()
            }
        }
    }

    func cancel() {
        runner.cancel()
    }

    // MARK: Repo selection & watch mode

    /// Set the repository; restarts the watcher if watch mode is on.
    func setRepo(_ url: URL) {
        repoURL = url
        lastDelta = nil
        if watchEnabled { startWatching() }
    }

    /// Toggle watch mode: auto re-scan (debounced) on file changes.
    func setWatch(_ enabled: Bool) {
        watchEnabled = enabled
        if enabled { startWatching() } else { watcher.stop() }
    }

    private func startWatching() {
        guard let repoURL else { watcher.stop(); return }
        watcher.onChange = { [weak self] in
            Task { @MainActor in self?.watchTriggeredRescan() }
        }
        watcher.start(url: repoURL)
    }

    private func watchTriggeredRescan() {
        guard watchEnabled else { return }
        if isScanning {
            rescanPending = true   // coalesce; the running scan re-runs on finish
        } else {
            run()
        }
    }

    /// Fold one progress event into observable state. A scan emits several
    /// analyzer sub-passes, so each `begin` resets the determinate bar; overall
    /// completion is signaled by the process exiting, not by any single `done`.
    private func apply(_ event: ProgressEvent) {
        switch event.kind {
        case .begin:
            indeterminate = false
            stopStageTimer()
            fraction = 0
            statusLabel = event.label ?? "Scanning files"
        case .advance:
            indeterminate = false
            stopStageTimer()
            if let fraction = event.fraction {
                self.fraction = fraction
                etaText = estimatedTimeRemaining(fraction: fraction)
            }
            currentFile = event.current ?? ""
        case .stage:
            indeterminate = true
            statusLabel = event.label ?? "Analyzing"
            currentFile = ""
            etaText = ""
            startStageTimer()
        case .done, .unknown:
            break
        }
    }

    // MARK: Indeterminate-phase timer

    private func startStageTimer() {
        stageTimerTask?.cancel()
        stageStartedAt = Date()
        stageElapsedText = "0:00"
        stageTimerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, self.indeterminate, let start = self.stageStartedAt else { break }
                self.stageElapsedText = Self.format(duration: Date().timeIntervalSince(start))
            }
        }
    }

    private func stopStageTimer() {
        guard stageTimerTask != nil else { return }
        stageTimerTask?.cancel()
        stageTimerTask = nil
        stageStartedAt = nil
        stageElapsedText = ""
    }

    /// If an LLM mode was requested but produced no artifact (usually: no
    /// backend — no API key and `claude` not found), return a message that
    /// includes the engine's own "skipped" line when we captured it.
    private func llmOutputWarning(config: ScanConfig, stderrTail: String) -> String? {
        guard let artifact = config.llmMode.artifactFilename else { return nil }
        let url = config.outputDirectory.appendingPathComponent(artifact)
        guard !FileManager.default.fileExists(atPath: url.path) else { return nil }
        let reason = stderrTail
            .split(separator: "\n")
            .last { $0.lowercased().contains("skip") }
        if let reason {
            return "\(config.llmMode.label): \(reason)"
        }
        return "\(config.llmMode.label) produced no output — check that an LLM backend "
            + "is available (an API key, or the `claude` CLI on your PATH)."
    }

    /// Linear ETA from elapsed time and the current determinate fraction.
    /// Empty until there's enough signal to be meaningful.
    private func estimatedTimeRemaining(fraction: Double) -> String {
        guard let startedAt, fraction > 0.02, fraction < 1 else { return "" }
        let elapsed = Date().timeIntervalSince(startedAt)
        let remaining = elapsed / fraction - elapsed
        return "~\(Self.format(duration: remaining)) left"
    }

    /// mm:ss (or h:mm) for a non-negative duration.
    static func format(duration seconds: Double) -> String {
        let total = Int(max(0, seconds))
        if total >= 3600 {
            return "\(total / 3600)h\(String(format: "%02dm", (total % 3600) / 60))"
        }
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
