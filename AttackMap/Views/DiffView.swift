import SwiftUI

/// The baseline diff (`attackmap-diff.md`): what this scan added, resolved,
/// or newly suppressed relative to the baseline report.
struct DiffView: View {
    let markdown: String?
    let baseline: URL?
    let gateFailed: Bool
    let baselineSupported: Bool

    var body: some View {
        if let markdown, !markdown.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            VStack(spacing: 0) {
                header
                Divider()
                ScrollView {
                    MarkdownText(markdown: markdown).padding(20)
                }
            }
        } else {
            ContentUnavailableView(
                "No baseline diff",
                systemImage: "plusminus",
                description: Text(emptyReason))
        }
    }

    private var emptyReason: String {
        if !baselineSupported {
            return "Baseline diffs need a newer attackmap (brew upgrade attackmap)."
        }
        if baseline == nil {
            return "This scan ran without a baseline. Rescan with Baseline set to Previous scan "
                + "(the default, once a repo has been scanned) or a report you choose."
        }
        return "The engine didn't write a diff for this scan."
    }

    private var header: some View {
        HStack(spacing: 8) {
            if gateFailed {
                Label("New HIGH findings vs. baseline", systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
            } else {
                Label("Compared with baseline", systemImage: "plusminus")
                    .foregroundStyle(.secondary)
            }
            if let baseline {
                Text(baseline.lastPathComponent)
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .help(baseline.path)
            }
            Spacer()
        }
        .font(.callout)
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}
