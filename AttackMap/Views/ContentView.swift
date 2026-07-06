import SwiftUI
import UniformTypeIdentifiers

/// M1/M2 skeleton: pick a repo, run a scan, watch live progress, and browse the
/// resulting findings. Rich per-section views (exploitability, paths, surface,
/// diagrams) land in later milestones.
struct ContentView: View {
    @State private var model = ScanViewModel()
    @State private var showingImporter = false

    var body: some View {
        VStack(spacing: 0) {
            controlBar
            Divider()
            progressBar
            Divider()
            content
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.repoURL = url
            }
        }
    }

    // MARK: Controls

    private var controlBar: some View {
        HStack(spacing: 12) {
            Button {
                showingImporter = true
            } label: {
                Label(model.repoURL?.lastPathComponent ?? "Choose repo…",
                      systemImage: "folder")
            }

            Picker("LLM", selection: $model.llmMode) {
                ForEach(ScanConfig.LLMMode.allCases) { mode in
                    Text(mode.label).tag(mode)
                }
            }
            .frame(maxWidth: 220)

            Toggle("CVE", isOn: $model.runCVE)

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

    // MARK: Progress

    @ViewBuilder private var progressBar: some View {
        HStack(spacing: 10) {
            switch model.phase {
            case .scanning:
                if model.indeterminate {
                    ProgressView().controlSize(.small)
                    Text(model.statusLabel).foregroundStyle(.secondary)
                } else {
                    ProgressView(value: model.fraction)
                        .frame(maxWidth: 260)
                    Text("\(Int(model.fraction * 100))%").monospacedDigit()
                    Text(model.currentFile)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            case .failed(let message):
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(message).foregroundStyle(.secondary).lineLimit(2)
            case .done:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text(model.statusLabel).foregroundStyle(.secondary)
            case .idle:
                Text("Choose a repository and run a scan.").foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .frame(height: 34)
    }

    // MARK: Results

    @ViewBuilder private var content: some View {
        if let report = model.report {
            Table(report.findingsByPriority) {
                TableColumn("Severity") { finding in
                    Text(finding.severity.capitalized)
                        .foregroundStyle(color(for: finding.severity))
                }
                .width(90)
                TableColumn("Finding", value: \.title)
                TableColumn("Confidence", value: \.confidence).width(100)
                TableColumn("Exploit") { finding in
                    Text(finding.exploitability.map(String.init) ?? "—")
                        .monospacedDigit()
                }
                .width(70)
            }
        } else {
            ContentUnavailableView(
                "No results yet",
                systemImage: "shield.lefthalf.filled",
                description: Text("Run a scan to see findings here."))
        }
    }

    private func color(for severity: String) -> Color {
        switch Severity(severity) {
        case .critical, .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        case .info, .unknown: return .secondary
        }
    }
}
