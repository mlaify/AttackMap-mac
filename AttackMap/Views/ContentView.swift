import SwiftUI
import UniformTypeIdentifiers

/// Top-level window: a control bar, a live-progress strip, and a
/// `NavigationSplitView` over the decoded report (Overview + Findings for M2;
/// exploitability / paths / surface / diagrams land in later milestones).
struct ContentView: View {
    @State private var model = ScanViewModel()
    @State private var section: Section? = .overview

    enum Section: String, CaseIterable, Identifiable, Hashable {
        case overview = "Overview"
        case findings = "Findings"
        case exploitability = "Exploitability"
        case paths = "Attack paths"
        case surface = "Attack surface"
        case diff = "Diff"
        case dependencies = "Dependencies"
        case secrets = "Secrets"
        case workflows = "CI workflows"
        case dataFlows = "Data flows"
        case analyzers = "Analyzers"
        case diagrams = "Diagrams"
        case review = "Review"
        case aiReview = "AI Review"
        var id: String { rawValue }
        var systemImage: String {
            switch self {
            case .overview: return "square.grid.2x2"
            case .findings: return "exclamationmark.shield"
            case .exploitability: return "flame"
            case .paths: return "arrow.triangle.branch"
            case .surface: return "point.topleft.down.to.point.bottomright.curvepath"
            case .diff: return "plusminus"
            case .dependencies: return "shippingbox"
            case .secrets: return "key"
            case .workflows: return "gearshape.2"
            case .dataFlows: return "arrow.triangle.pull"
            case .analyzers: return "puzzlepiece.extension"
            case .diagrams: return "flowchart"
            case .review: return "doc.text"
            case .aiReview: return "sparkles"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            controlBar
            if model.llmMode != .none {
                Divider()
                llmOptionsBar
            }
            if model.llmMode == .huntVerify, model.capabilities?.huntJury ?? true {
                Divider()
                juryBar
            }
            Divider()
            progressBar
            Divider()
            resultsArea
        }
        .task { model.loadAvailableModules() }
        .alert("Export failed", isPresented: Binding(
            get: { exportError != nil }, set: { if !$0 { exportError = nil } })) {
            Button("OK") { exportError = nil }
        } message: {
            Text(exportError ?? "")
        }
    }

    /// Present the folder picker; one folder → single-repo scan, two or more →
    /// cross-repo fleet scan.
    private func chooseRepos() {
        let urls = FolderPicker.chooseDirectories(allowMultiple: true)
        if !urls.isEmpty { model.setFleetRepos(urls) }
    }

    // MARK: Verify-jury tuning (Hunt + verify only)

    private var juryBar: some View {
        HStack(spacing: 16) {
            Label("Verify jury", systemImage: "person.3")
                .font(.caption).foregroundStyle(.secondary)
            Stepper("Votes \(model.jury.verifyVotes)",
                    value: $model.jury.verifyVotes, in: 1...9)
                .help("Independent skeptic passes; a strict majority CONFIRMs a lead.")
            Stepper("Lenses \(model.jury.lenses)",
                    value: $model.jury.lenses, in: 1...6)
                .help("Failure-mode generation passes (auth-bypass, TOCTOU, IDOR, …), deduped before verify.")
            Stepper("Rounds \(model.jury.rounds)",
                    value: $model.jury.rounds, in: 1...5)
                .help("Loop generation until a round finds nothing new (a completeness critic seeds each next round).")
            if model.jury.rounds > 1 {
                Stepper("Budget \(model.jury.budget / 1000)k",
                        value: $model.jury.budget, in: 0...500_000, step: 25_000)
                    .help("Stop launching new rounds past this many output tokens (0 = no cap).")
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .frame(height: 34)
        .disabled(model.isScanning)
    }

    // MARK: LLM options (shown only when an LLM mode is selected)

    private var llmOptionsBar: some View {
        HStack(spacing: 12) {
            Picker("Provider", selection: $model.provider) {
                ForEach(ScanConfig.Provider.allCases) { Text($0.label).tag($0) }
            }
            .frame(maxWidth: 190)

            // The model list depends on the provider.
            switch model.provider {
            case .claude:
                Picker("Model", selection: $model.model) {
                    ForEach(ScanConfig.LLMModel.allCases) { Text($0.label).tag($0) }
                }
                .frame(maxWidth: 190)
            case .openai:
                Picker("Model", selection: $model.openAIModel) {
                    ForEach(ScanConfig.OpenAIModel.allCases) { Text($0.label).tag($0) }
                }
                .frame(maxWidth: 190)
            }

            Picker("Reasoning", selection: $model.effort) {
                ForEach(ScanConfig.Effort.allCases) { Text($0.label).tag($0) }
            }
            .frame(maxWidth: 180)

            // Fast mode is Claude-only (Opus 4.8/4.7); hidden for OpenAI.
            if model.provider == .claude {
                Toggle("Fast", isOn: $model.fast)
                    .disabled(!model.model.fastCapable)
                    .help(model.model.fastCapable
                          ? "~2.5× faster output (premium). Needs an API key in Settings."
                          : "Fast mode is only available on Opus 4.8 / 4.7.")
            }

            Spacer()
        }
        .padding(.horizontal, 12)
        .frame(height: 34)
        .disabled(model.isScanning)
    }

    private var repoButtonTitle: String {
        if model.isFleet { return "\(model.fleetRepoURLs.count) repos (fleet)" }
        return model.repoURL?.lastPathComponent ?? "Choose repo…"
    }

    // MARK: Control bar

    private var controlBar: some View {
        HStack(spacing: 12) {
            Button { chooseRepos() } label: {
                Label(repoButtonTitle, systemImage: model.isFleet ? "square.stack.3d.up" : "folder")
            }
            .help("Choose one repository, or select several for a cross-repo fleet scan.")

            Picker("LLM", selection: $model.llmMode) {
                ForEach(ScanConfig.LLMMode.allCases) { Text($0.label).tag($0) }
            }
            .frame(maxWidth: 220)
            .disabled(model.isScanning || model.isFleet)
            .help(model.isFleet ? "LLM modes run per-repo; they don't apply to a fleet scan." : "")

            Toggle("CVE", isOn: $model.runCVE).disabled(model.isScanning)

            Toggle("Recall", isOn: $model.recall)
                .disabled(model.isScanning || model.capabilities?.recall == false)
                .help(model.capabilities?.recall == false
                      ? "Recall mode needs attackmap ≥ 0.4.20 (brew upgrade attackmap)."
                      : "Wider, speculative taint discovery (--recall). Extra reach is "
                        + "marked speculative; pair with Hunt + verify to adjudicate it.")

            analyzersMenu

            suppressionMenu

            baselineMenu

            Toggle("Watch", isOn: Binding(
                get: { model.watchEnabled },
                set: { model.setWatch($0) }))
            .help("Auto re-scan when files change")
            .disabled(model.repoURL == nil)

            Spacer()

            if model.isScanning {
                Button(role: .destructive) { model.cancel() } label: {
                    Label("Cancel", systemImage: "stop.fill")
                }
            } else {
                Button { model.run() } label: {
                    Label("Run scan", systemImage: "play.fill")
                }
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(!model.canRun)
            }
        }
        .padding(12)
    }

    /// Analyzer selection. "Automatic" (default, empty selection) lets the
    /// engine pick analyzers by repo language; the user can instead pin one or
    /// more specific modules. Disabled when the installed CLI is too old to
    /// report modules (`modules --json`, ≥ 0.4.4).
    private var analyzersMenu: some View {
        Menu {
            Toggle("Automatic (all relevant)", isOn: Binding(
                get: { model.selectedModules.isEmpty },
                set: { on in if on { model.selectedModules = [] } }))
            if !model.availableModules.isEmpty {
                Divider()
                ForEach(model.availableModules) { mod in
                    Toggle(mod.displayName, isOn: Binding(
                        get: { model.selectedModules.contains(mod.name) },
                        set: { on in
                            if on { model.selectedModules.insert(mod.name) }
                            else { model.selectedModules.remove(mod.name) }
                        }))
                }
            }
        } label: {
            Label(analyzersTitle, systemImage: "puzzlepiece.extension")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(model.isScanning || model.availableModules.isEmpty)
        .help(model.availableModules.isEmpty
              ? "Update attackmap to ≥ 0.4.4 to choose specific analyzers."
              : "Which analyzers run. Automatic lets the engine pick by repo language.")
    }

    private var analyzersTitle: String {
        model.selectedModules.isEmpty
            ? "Analyzers: Auto"
            : "Analyzers: \(model.selectedModules.count)"
    }

    /// Suppression controls (#144, ≥ 0.4.7): ignore all suppressions for a full
    /// audit, or point at an explicit `.attackmap-suppress.yaml` baseline.
    private var suppressionMenu: some View {
        Menu {
            Toggle("Ignore all suppressions", isOn: $model.noSuppress)
                .help("Full, unfiltered audit — surface findings the suppress file/inline directives silence.")
            Divider()
            Button("Choose suppress file…") {
                if let url = FolderPicker.chooseFile(contentTypes: [.yaml, .item]) {
                    model.suppressFileURL = url
                }
            }
            if model.suppressFileURL != nil {
                Button("Use auto-discovered file") { model.suppressFileURL = nil }
                Text(model.suppressFileURL?.lastPathComponent ?? "")
            }
        } label: {
            Label(suppressionTitle, systemImage: "eye.slash")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(model.isScanning || model.capabilities?.suppress == false)
        .help(model.capabilities?.suppress == false
              ? "Suppression controls need attackmap ≥ 0.4.7."
              : "Finding suppression (.attackmap-suppress.yaml / inline directives).")
    }

    /// Baseline diff (`--baseline`): the previous scan of this repo by
    /// default, none, or a report the user picks (e.g. one from CI on main).
    /// Single-repo only — the engine rejects baselines in fleet mode.
    private var baselineMenu: some View {
        Menu {
            Picker("Baseline", selection: $model.baselineChoice) {
                Text(model.hasPreviousReport ? "Previous scan" : "Previous scan (none yet)")
                    .tag(BaselineChoice.previousScan)
                Text("None").tag(BaselineChoice.none)
                if case .custom(let url) = model.baselineChoice {
                    Text(url.lastPathComponent).tag(model.baselineChoice)
                }
            }
            .pickerStyle(.inline)
            Button("Choose baseline report…") {
                if let url = FolderPicker.chooseFile(contentTypes: [.json]) {
                    model.baselineChoice = .custom(url)
                }
            }
            Divider()
            Toggle("Fail on new HIGH findings", isOn: $model.failOnNewHigh)
                .disabled(model.capabilities?.failOnNewHigh == false || model.baselineChoice == .none)
            Toggle("Generate PR comment", isOn: $model.generatePRComment)
                .disabled(model.capabilities?.prComment == false)
        } label: {
            Label(baselineTitle, systemImage: "plusminus")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(model.isScanning || model.isFleet || model.capabilities?.baseline == false)
        .help(model.capabilities?.baseline == false
              ? "Baseline diffs need a newer attackmap (brew upgrade attackmap)."
              : model.isFleet ? "Baselines apply to single-repo scans."
              : "Diff this scan against a baseline report (--baseline); see the Diff tab.")
    }

    private var baselineTitle: String {
        switch model.baselineChoice {
        case .none: return "Baseline: none"
        case .previousScan: return "Baseline: previous"
        case .custom: return "Baseline: custom"
        }
    }

    private var suppressionTitle: String {
        if model.noSuppress { return "Suppress: off" }
        if model.suppressFileURL != nil { return "Suppress: custom" }
        return "Suppress: auto"
    }

    // MARK: Progress strip

    @ViewBuilder private var progressBar: some View {
        HStack(spacing: 10) {
            switch model.phase {
            case .scanning:
                if model.indeterminate {
                    ProgressView().controlSize(.small)
                    Text(model.statusLabel).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail)
                    if !model.stageElapsedText.isEmpty {
                        Text(model.stageElapsedText)
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                } else {
                    ProgressView(value: model.fraction).frame(maxWidth: 240)
                    Text("\(Int(model.fraction * 100))%").monospacedDigit()
                    if !model.etaText.isEmpty {
                        Text(model.etaText).font(.caption).foregroundStyle(.secondary)
                    }
                    Text(model.currentFile)
                        .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            case .failed(let message):
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(message).foregroundStyle(.secondary).lineLimit(2)
            case .done:
                Image(systemName: model.warning == nil ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(model.warning == nil ? Color.green : .orange)
                if let warning = model.warning {
                    Text(warning).foregroundStyle(.secondary).lineLimit(2)
                } else {
                    Text(model.statusLabel).foregroundStyle(.secondary)
                }
                if let delta = model.lastDelta, delta.added > 0 || delta.resolved > 0 {
                    Text("+\(delta.added) new · \(delta.resolved) resolved")
                        .font(.caption)
                        .foregroundStyle(delta.added > 0 ? Color.orange : .green)
                }
                if model.watchEnabled {
                    Label("Watching", systemImage: "eye")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if model.report != nil {
                    exportMenu
                }
                if let dir = model.outputDirectory {
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([dir])
                    } label: {
                        Label("Reveal Reports", systemImage: "folder")
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help(dir.path)
                }
            case .idle:
                Text("Choose a repository and run a scan.").foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .frame(height: 34)
    }

    // MARK: Export

    /// Save copies of the report artifacts, open the SARIF in the default
    /// handler, or generate the PR comment on a rescan.
    private var exportMenu: some View {
        Menu {
            if let sarif = model.sarifURL {
                Button("Save SARIF…") { export(sarif, "attackmap-report.sarif", ReportExporter.sarifType) }
                Button("Open SARIF in Default App") { ReportExporter.openInDefaultApp(sarif) }
                Button("Reveal SARIF in Finder") { ReportExporter.reveal(sarif) }
            } else {
                Text("No SARIF report for this scan")
            }
            Divider()
            if let json = model.reportJSONURL {
                Button("Save Report JSON…") { export(json, "attackmap-report.json", .json) }
                Button("Open Report JSON in Default App") { ReportExporter.openInDefaultApp(json) }
            }
            Divider()
            if let comment = model.prCommentURL {
                Button("Save PR Comment…") {
                    export(comment, ScanViewModel.prCommentFilename, ReportExporter.markdownType)
                }
                Button("Copy PR Comment") {
                    if let text = try? String(contentsOf: comment, encoding: .utf8) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(text, forType: .string)
                    }
                }
            } else if model.capabilities?.prComment != false {
                Button("Generate PR Comment (Rescan)") {
                    model.generatePRComment = true
                    model.run()
                }
                .disabled(!model.canRun)
            }
        } label: {
            Label("Export", systemImage: "square.and.arrow.up")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .font(.caption)
    }

    @State private var exportError: String?

    private func export(_ source: URL, _ name: String, _ type: UTType) {
        do {
            try ReportExporter.saveCopy(of: source, suggestedName: name, contentType: type)
        } catch {
            exportError = error.localizedDescription
        }
    }

    // MARK: Results

    private var suppressContext: SuppressContext? {
        guard let target = model.suppressTargetURL else { return nil }
        return SuppressContext(
            targetURL: target,
            suppressionsIgnored: model.noSuppress,
            canRescan: model.canRun,
            rescan: { [model] in model.run() })
    }

    @ViewBuilder private var resultsArea: some View {
        if case .failed(let message) = model.phase {
            ScanErrorView(message: message, detail: model.failureDetail)
        } else if let fleet = model.fleet {
            FleetView(fleet: fleet, graphDirectory: model.outputDirectory)
        } else if let report = model.report {
            NavigationSplitView {
                List(Section.allCases, selection: $section) { item in
                    Label(item.rawValue, systemImage: item.systemImage).tag(item)
                }
                .navigationSplitViewColumnWidth(min: 160, ideal: 180, max: 240)
            } detail: {
                switch section ?? .overview {
                case .overview: OverviewView(report: report)
                case .findings: FindingsView(report: report, suppressContext: suppressContext)
                case .exploitability: ExploitabilityView(report: report)
                case .paths: AttackPathsView(report: report)
                case .surface: AttackSurfaceView(report: report)
                case .diff:
                    DiffView(markdown: model.diffMarkdown, baseline: model.baselineUsed,
                             gateFailed: model.newHighGateFailed,
                             baselineSupported: model.capabilities?.baseline ?? true)
                case .dependencies: DependenciesView(scan: report.scan, cveRan: model.lastScanRanCVE)
                case .secrets: SecretsView(scan: report.scan)
                case .workflows: WorkflowIssuesView(scan: report.scan)
                case .dataFlows: DataFlowsView(scan: report.scan)
                case .analyzers: AnalyzersView(report: report)
                case .diagrams: DiagramView(outputDirectory: model.outputDirectory)
                case .review: ReviewView(report: report)
                case .aiReview: AIReviewView(outputDirectory: model.outputDirectory)
                }
            }
        } else {
            emptyState
        }
    }

    @ViewBuilder private var emptyState: some View {
        let recents = RecentScansStore.all()
        VStack(spacing: 16) {
            ContentUnavailableView(
                "No results yet",
                systemImage: "shield.lefthalf.filled",
                description: Text("Choose a repository and run a scan."))
            if !recents.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("RECENT").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                    ForEach(recents) { recent in
                        Button {
                            model.setRepo(recent.url)
                        } label: {
                            Label(recent.name, systemImage: "folder")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(maxWidth: 280)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Full-height view for a failed scan: the summary line plus the CLI's captured
/// stderr/stdout tail (selectable + scrollable), so failures aren't opaque.
private struct ScanErrorView: View {
    let message: String
    let detail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            if let detail, !detail.isEmpty {
                Text("Output from attackmap")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ScrollView {
                    Text(detail)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
            } else {
                Text("No further output was captured. Re-run from a terminal for the full error.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(16)
    }
}
