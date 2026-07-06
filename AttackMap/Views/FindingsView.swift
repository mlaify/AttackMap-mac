import SwiftUI

/// Findings master-detail: a priority-ordered list on the left, full detail on
/// the right.
struct FindingsView: View {
    let report: Report
    @State private var selection: Finding.ID?

    private var findings: [Finding] { report.findingsByPriority }

    var body: some View {
        HSplitView {
            List(findings, selection: $selection) { finding in
                FindingRow(finding: finding).tag(finding.id)
            }
            .frame(minWidth: 300, idealWidth: 340)

            Group {
                if let selection, let finding = findings.first(where: { $0.id == selection }) {
                    FindingDetailView(finding: finding)
                } else {
                    ContentUnavailableView(
                        "Select a finding",
                        systemImage: "hand.point.up.left",
                        description: Text("\(findings.count) findings, most severe first."))
                }
            }
            .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .onAppear { if selection == nil { selection = findings.first?.id } }
    }
}

private struct FindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(spacing: 8) {
            SeverityBadge(severity: finding.severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).lineLimit(2)
                Text("confidence \(finding.confidence)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let score = finding.exploitability {
                Text("\(score)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}
