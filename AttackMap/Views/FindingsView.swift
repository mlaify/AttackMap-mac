import SwiftUI

/// Findings master-detail: a priority-ordered list on the left, full detail on
/// the right.
struct FindingsView: View {
    let report: Report
    @State private var selection: Finding.ID?

    private var findings: [Finding] { report.findingsByPriority }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                List(findings, selection: $selection) { finding in
                    FindingRow(finding: finding).tag(finding.id)
                }
                if !report.suppressedFindings.isEmpty {
                    Divider()
                    SuppressedPane(items: report.suppressedFindings)
                }
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

/// Collapsible summary of findings the engine silenced via suppression rules
/// (#144). Shown, not hidden, so an audit can see what was quieted and why.
private struct SuppressedPane: View {
    let items: [SuppressedFinding]
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(items.sorted { $0.severityRank > $1.severityRank }) { item in
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 6) {
                                SeverityBadge(severity: item.severity)
                                Text(item.title).lineLimit(2).font(.callout)
                            }
                            if let reason = item.reason, !reason.isEmpty {
                                Text(reason).font(.caption).foregroundStyle(.secondary)
                            }
                            if let rule = item.rule, !rule.isEmpty {
                                Text("rule: \(rule)").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.vertical, 4)
            }
            .frame(maxHeight: 180)
        } label: {
            Label("Suppressed (\(items.count))", systemImage: "eye.slash")
                .font(.callout)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
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
