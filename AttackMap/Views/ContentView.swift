import SwiftUI
import UniformTypeIdentifiers

/// Top-level window: a control bar, a live-progress strip, and a
/// `NavigationSplitView` over the decoded report (Overview + Findings for M2;
/// exploitability / paths / surface / diagrams land in later milestones).
struct ContentView: View {
    @State private var model = ScanViewModel()
    @State private var showingImporter = false
    @State private var section: Section? = .overview

    enum Section: String, CaseIterable, Identifiable, Hashable {
        case overview = "Overview"
        case findings = "Findings"
        case exploitability = "Exploitability"
        case paths = "Attack paths"
        case surface = "Attack surface"
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
            Divider()
            progressBar
            Divider()
            resultsArea
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.setRepo(url)
            }
        }
        .task { model.loadAvailableModules() }
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

    // MARK: Control bar

    private var controlBar: some View {
        HStack(spacing: 12) {
            Button { showingImporter = true } label: {
                Label(model.repoURL?.lastPathComponent ?? "Choose repo…", systemImage: "folder")
            }

            Picker("LLM", selection: $model.llmMode) {
                ForEach(ScanConfig.LLMMode.allCases) { Text($0.label).tag($0) }
            }
            .frame(maxWidth: 220)
            .disabled(model.isScanning)

            Toggle("CVE", isOn: $model.runCVE).disabled(model.isScanning)

            analyzersMenu

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
            case .idle:
                Text("Choose a repository and run a scan.").foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .frame(height: 34)
    }

    // MARK: Results

    @ViewBuilder private var resultsArea: some View {
        if let report = model.report {
            NavigationSplitView {
                List(Section.allCases, selection: $section) { item in
                    Label(item.rawValue, systemImage: item.systemImage).tag(item)
                }
                .navigationSplitViewColumnWidth(min: 160, ideal: 180, max: 240)
            } detail: {
                switch section ?? .overview {
                case .overview: OverviewView(report: report)
                case .findings: FindingsView(report: report)
                case .exploitability: ExploitabilityView(report: report)
                case .paths: AttackPathsView(report: report)
                case .surface: AttackSurfaceView(report: report)
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
