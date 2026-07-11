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
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text(model.statusLabel).foregroundStyle(.secondary)
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
