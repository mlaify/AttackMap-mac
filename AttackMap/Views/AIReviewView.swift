import SwiftUI

/// Surfaces Claude's LLM outputs, which the engine writes as standalone
/// markdown files (not part of `attackmap-report.json`):
/// `defensive-review-llm.md` (--llm), `vulnerability-hypotheses.md`
/// (--hunt / --hunt --verify), and `remediation.md` (--remediate). Only the
/// artifacts that actually exist for this scan are shown.
struct AIReviewView: View {
    let outputDirectory: URL?

    @State private var artifacts: [Artifact] = []
    @State private var selection: String?

    private struct Artifact: Identifiable, Hashable {
        let id: String       // filename, stable
        let label: String
        let markdown: String
    }

    private static let specs: [(file: String, label: String)] = [
        ("defensive-review-llm.md", "Review"),
        ("vulnerability-hypotheses.md", "Hunt"),
        ("remediation.md", "Remediation"),
    ]

    var body: some View {
        Group {
            if artifacts.isEmpty {
                ContentUnavailableView(
                    "No AI output",
                    systemImage: "sparkles",
                    description: Text("Run a scan with an LLM mode (Review, Hunt, or Remediate) to see Claude's output here."))
            } else {
                VStack(spacing: 0) {
                    if artifacts.count > 1 {
                        Picker("Artifact", selection: $selection) {
                            ForEach(artifacts) { Text($0.label).tag(Optional($0.id)) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .padding(8)
                        Divider()
                    }
                    ScrollView {
                        if let selection, let artifact = artifacts.first(where: { $0.id == selection }) {
                            MarkdownText(markdown: artifact.markdown).padding(20)
                        }
                    }
                }
            }
        }
        .task(id: outputDirectory?.path) { load() }
    }

    private func load() {
        guard let dir = outputDirectory else {
            artifacts = []
            selection = nil
            return
        }
        var found: [Artifact] = []
        for spec in Self.specs {
            let url = dir.appendingPathComponent(spec.file)
            guard let text = try? String(contentsOf: url, encoding: .utf8),
                  !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { continue }
            found.append(Artifact(id: spec.file, label: spec.label, markdown: text))
        }
        artifacts = found
        if selection == nil || !found.contains(where: { $0.id == selection }) {
            selection = found.first?.id
        }
    }
}
