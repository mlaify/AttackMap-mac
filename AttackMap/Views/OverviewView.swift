import SwiftUI

/// At-a-glance summary of a completed scan.
struct OverviewView: View {
    let report: Report

    private var rootName: String {
        guard let root = report.scan?.root, !root.isEmpty else { return "Scan results" }
        return URL(fileURLWithPath: root).lastPathComponent
    }

    private var severityCounts: [(Severity, Int)] {
        let grouped = Dictionary(grouping: report.findings) { Severity($0.severity) }
        let order: [Severity] = [.critical, .high, .medium, .low, .info]
        return order.compactMap { sev in
            let count = grouped[sev]?.count ?? 0
            return count > 0 ? (sev, count) : nil
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text(rootName).font(.title2.weight(.semibold))

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 12)], spacing: 12) {
                    StatCard(title: "Findings", value: "\(report.findings.count)", systemImage: "exclamationmark.shield")
                    StatCard(title: "Files scanned", value: "\(report.scan?.filesScanned ?? 0)", systemImage: "doc.text.magnifyingglass")
                    StatCard(title: "Routes", value: "\(report.scan?.routes.count ?? 0)", systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                    StatCard(title: "Attack paths", value: "\(report.attackPaths.count)", systemImage: "arrow.triangle.branch")
                    StatCard(title: "Exploitable sinks", value: "\(report.exploitability.count)", systemImage: "flame")
                    StatCard(title: "Languages", value: languagesText, systemImage: "chevron.left.forwardslash.chevron.right")
                }

                if !severityCounts.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        sectionTitle("Findings by severity")
                        HStack(spacing: 10) {
                            ForEach(severityCounts, id: \.0) { sev, count in
                                HStack(spacing: 6) {
                                    SeverityBadge(severity: sev.rawValue)
                                    Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }

                if let top = report.exploitability.sorted(by: { $0.score > $1.score }).first {
                    VStack(alignment: .leading, spacing: 8) {
                        sectionTitle("Most exploitable now")
                        HStack(spacing: 10) {
                            Text("\(top.score)")
                                .font(.title.weight(.bold)).monospacedDigit()
                                .foregroundStyle(top.score >= 70 ? .red : .orange)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(top.subject).fontWeight(.medium)
                                Text(top.location).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var languagesText: String {
        let langs = report.scan?.languages ?? []
        return langs.isEmpty ? "—" : langs.joined(separator: ", ")
    }

    private func sectionTitle(_ text: String) -> some View {
        Text(text.uppercased()).font(.caption.weight(.bold)).foregroundStyle(.secondary)
    }
}

private struct StatCard: View {
    let title: String
    let value: String
    let systemImage: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage)
                .font(.caption).foregroundStyle(.secondary)
                .labelStyle(.titleAndIcon)
            Text(value).font(.title3.weight(.semibold)).lineLimit(1).minimumScaleFactor(0.6)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }
}
