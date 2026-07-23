import SwiftUI

/// Cross-repo (fleet) results: per-repo rollup plus the cross-boundary flows,
/// trust-assumption gaps, control anomalies, and contract links the engine finds
/// across the whole set (#146). Cross-repo signals are SPECULATIVE by design —
/// leads for a human to confirm, not detections.
struct FleetView: View {
    let fleet: FleetSummary
    let graphDirectory: URL?
    @State private var section: Section = .overview

    enum Section: String, CaseIterable, Identifiable, Hashable {
        case overview = "Overview"
        case crossBoundary = "Cross-boundary"
        case trustGaps = "Trust gaps"
        case anomalies = "Control anomalies"
        case links = "Contract links"
        case graph = "Fleet graph"
        var id: String { rawValue }
        var systemImage: String {
            switch self {
            case .overview: return "square.grid.2x2"
            case .crossBoundary: return "arrow.left.arrow.right"
            case .trustGaps: return "lock.open.trianglebadge.exclamationmark"
            case .anomalies: return "exclamationmark.triangle"
            case .links: return "link"
            case .graph: return "point.3.connected.trianglepath.dotted"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { item in
                Label {
                    HStack {
                        Text(item.rawValue)
                        Spacer()
                        if let n = badge(for: item), n > 0 {
                            Text("\(n)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                } icon: {
                    Image(systemName: item.systemImage)
                }
                .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            switch section {
            case .overview: overview
            case .crossBoundary: crossBoundaryList
            case .trustGaps: trustGapList
            case .anomalies: anomalyList
            case .links: linkList
            case .graph: DiagramView(outputDirectory: graphDirectory, filenames: ["fleet-graph.md"])
            }
        }
    }

    private func badge(for item: Section) -> Int? {
        switch item {
        case .crossBoundary: return fleet.crossBoundaryFlows.count
        case .trustGaps: return fleet.trustGaps.count
        case .anomalies: return fleet.crossRepoAnomalies.count
        case .links: return fleet.crossRepoLinks.count
        default: return nil
        }
    }

    // MARK: Overview

    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    StatCard(title: "Repos", value: "\(fleet.repoCount)", systemImage: "square.stack.3d.up")
                    StatCard(title: "Findings", value: "\(fleet.totalFindings)", systemImage: "exclamationmark.shield")
                    StatCard(title: "Cross-repo signals", value: "\(fleet.crossRepoSignalCount)",
                             systemImage: "arrow.left.arrow.right", tint: fleet.crossRepoSignalCount > 0 ? .orange : .secondary)
                }

                Text("Repositories").font(.headline)
                Table(fleet.repos) {
                    TableColumn("Repo") { Text($0.repoId).fontWeight(.medium) }
                    TableColumn("Findings") { Text("\($0.findings)").monospacedDigit() }
                    TableColumn("Critical") { r in count(r, .critical) }
                    TableColumn("High") { r in count(r, .high) }
                    TableColumn("Medium") { r in count(r, .medium) }
                    TableColumn("Suppressed") { Text("\($0.suppressed)").monospacedDigit().foregroundStyle(.secondary) }
                }
                .frame(minHeight: 160, maxHeight: 320)

                if fleet.crossRepoSignalCount == 0 {
                    Text("No cross-repo signals — the fleet's boundaries, trust assumptions, and controls look consistent across the repos scanned. Contract links (if any) are under the Contract links tab.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .padding(16)
        }
    }

    @ViewBuilder private func count(_ repo: FleetRepo, _ sev: Severity) -> some View {
        let n = repo.count(sev)
        Text(n == 0 ? "—" : "\(n)").monospacedDigit()
            .foregroundStyle(n == 0 ? .secondary : .primary)
    }

    // MARK: Cross-boundary flows

    private var crossBoundaryList: some View {
        SignalScroll(
            isEmpty: fleet.crossBoundaryFlows.isEmpty,
            emptyTitle: "No cross-boundary flows",
            emptyHint: "A confused-deputy flow is a client in one repo driving a server route in another that reaches a dangerous sink or an unguarded object reference."
        ) {
            ForEach(fleet.crossBoundaryFlows.sorted { $0.severityRank > $1.severityRank }) { f in
                SignalCard(
                    severity: f.severity, speculative: true,
                    title: "\(f.method) \(f.route)",
                    subtitle: "\(f.clientRepo) → \(f.serverRepo) · \(f.basis)",
                    detail: f.detail,
                    locations: [("caller", f.clientLocation), ("route", f.serverLocation)])
            }
        }
    }

    // MARK: Trust gaps

    private var trustGapList: some View {
        SignalScroll(
            isEmpty: fleet.trustGaps.isEmpty,
            emptyTitle: "No trust-assumption gaps",
            emptyHint: "A trust gap is a state-changing cross-repo call landing on a server route with no detectable auth control."
        ) {
            ForEach(fleet.trustGaps.sorted { $0.severityRank > $1.severityRank }) { g in
                SignalCard(
                    severity: g.severity, speculative: true,
                    title: "\(g.method) \(g.route)",
                    subtitle: "\(g.clientRepo) → \(g.serverRepo) · no auth on a state-changing route",
                    detail: nil,
                    locations: [("caller", g.clientLocation), ("route", g.serverLocation)])
            }
        }
    }

    // MARK: Control anomalies

    private var anomalyList: some View {
        SignalScroll(
            isEmpty: fleet.crossRepoAnomalies.isEmpty,
            emptyTitle: "No cross-repo control anomalies",
            emptyHint: "An anomaly is a repo that omits an auth control its peers enforce on the same route template."
        ) {
            ForEach(fleet.crossRepoAnomalies.sorted { $0.severityRank > $1.severityRank }) { a in
                SignalCard(
                    severity: a.severity, speculative: true,
                    title: "\(a.method) \(a.route)",
                    subtitle: "`\(a.repo)` serves /\(a.template) with no auth",
                    detail: a.peers.isEmpty ? nil : "Peers guarding it: \(a.peers.joined(separator: ", "))",
                    locations: [])
            }
        }
    }

    // MARK: Contract links

    private var linkList: some View {
        Group {
            if fleet.crossRepoLinks.isEmpty {
                ContentUnavailableView(
                    "No contract links",
                    systemImage: "link",
                    description: Text("No outbound call in one repo matched a served route in another."))
            } else {
                Table(fleet.crossRepoLinks) {
                    TableColumn("Client") { Text($0.clientRepo) }
                    TableColumn("Method") { Text($0.method).monospaced() }
                    TableColumn("Route") { Text("/\($0.pathTemplate)").monospaced() }
                    TableColumn("Server") { Text($0.serverRepo) }
                    TableColumn("Caller") { Text($0.clientLocation).font(.caption).foregroundStyle(.secondary) }
                }
            }
        }
    }
}

/// A titled stat tile for the fleet overview.
private struct StatCard: View {
    let title: String
    let value: String
    let systemImage: String
    var tint: Color = .accentColor

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: systemImage)
                .font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title2.bold().monospacedDigit()).foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// Scrollable container for a list of signal cards, with a shared empty state.
private struct SignalScroll<Content: View>: View {
    let isEmpty: Bool
    let emptyTitle: String
    let emptyHint: String
    @ViewBuilder var content: Content

    var body: some View {
        if isEmpty {
            ContentUnavailableView(
                emptyTitle, systemImage: "checkmark.circle",
                description: Text(emptyHint))
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) { content }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
        }
    }
}

/// One cross-repo signal, rendered as a card with a severity badge and a
/// SPECULATIVE marker (all cross-repo findings are leads, not detections).
private struct SignalCard: View {
    let severity: String
    let speculative: Bool
    let title: String
    let subtitle: String
    let detail: String?
    let locations: [(String, String)]

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                SeverityBadge(severity: severity)
                if speculative {
                    Text("SPECULATIVE")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(.orange.opacity(0.18), in: Capsule())
                        .foregroundStyle(.orange)
                }
                Text(title).font(.callout.monospaced().weight(.medium))
            }
            Text(subtitle).font(.callout).foregroundStyle(.secondary)
            if let detail, !detail.isEmpty {
                Text(detail).font(.callout)
            }
            if !locations.isEmpty {
                HStack(spacing: 14) {
                    ForEach(Array(locations.enumerated()), id: \.offset) { _, pair in
                        if !pair.1.isEmpty {
                            Text("\(pair.0): \(pair.1)")
                                .font(.caption.monospaced()).foregroundStyle(.tertiary)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
    }
}
