import SwiftUI

/// Attack paths as numbered step chains, each with its impact.
struct AttackPathsView: View {
    let report: Report

    var body: some View {
        if report.attackPaths.isEmpty {
            ContentUnavailableView(
                "No attack paths",
                systemImage: "arrow.triangle.branch",
                description: Text("No multi-step chains were assembled from the findings."))
        } else {
            List {
                ForEach(report.attackPaths) { path in
                    Section {
                        ForEach(Array(path.steps.enumerated()), id: \.offset) { index, step in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("\(index + 1)")
                                    .font(.caption.monospaced().weight(.bold))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 18, alignment: .trailing)
                                Text(step).textSelection(.enabled)
                            }
                        }
                        if !path.impact.isEmpty {
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange).font(.caption)
                                Text(path.impact).font(.callout).foregroundStyle(.secondary)
                            }
                        }
                    } header: {
                        Text(path.name).font(.headline)
                    }
                }
            }
        }
    }
}
