import SwiftUI

// Panes over the inventory sections of `scan`: dependencies + CVEs, secrets,
// CI workflow issues, data flows, and analyzer status / provenance.

private func location(_ file: String, _ line: Int?) -> String {
    guard !file.isEmpty else { return "—" }
    return line.map { "\(file):\($0)" } ?? file
}

/// Small capsule naming the analyzer that produced a signal (`source_analyzer`).
struct ProvenanceBadge: View {
    let analyzer: String?

    var body: some View {
        if let analyzer, !analyzer.isEmpty {
            Text(analyzer)
                .font(.caption2.monospaced())
                .padding(.horizontal, 6).padding(.vertical, 1)
                .background(.blue.opacity(0.12), in: Capsule())
                .foregroundStyle(.blue)
                .help("Reported by the \(analyzer) analyzer")
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }
}

// MARK: Dependencies & vulnerabilities

struct DependenciesView: View {
    let scan: Scan?
    /// Whether the scan that produced this report ran `--cve`.
    let cveRan: Bool

    private var dependencies: [Dependency] {
        (scan?.dependencies ?? []).sorted {
            ($0.ecosystem, $0.name.lowercased(), $0.file) < ($1.ecosystem, $1.name.lowercased(), $1.file)
        }
    }

    private var vulnerabilities: [Vulnerability] {
        (scan?.vulnerabilities ?? []).sorted {
            if $0.severityRank != $1.severityRank { return $0.severityRank > $1.severityRank }
            return ($0.cvssScore ?? 0) > ($1.cvssScore ?? 0)
        }
    }

    private var showProvenance: Bool { dependencies.contains { $0.sourceAnalyzer != nil } }

    var body: some View {
        if dependencies.isEmpty && vulnerabilities.isEmpty {
            ContentUnavailableView(
                "No dependencies found",
                systemImage: "shippingbox",
                description: Text("No manifests or lockfiles (requirements.txt, package.json, go.mod, Cargo.toml, …) were detected."))
        } else {
            VSplitView {
                vulnerabilityPane
                    .frame(minHeight: 140, idealHeight: vulnerabilities.isEmpty ? 140 : 260)
                dependencyPane
                    .frame(minHeight: 160)
            }
        }
    }

    @ViewBuilder private var vulnerabilityPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            paneHeader("Known vulnerabilities (\(vulnerabilities.count))", systemImage: "ladybug")
            if vulnerabilities.isEmpty {
                Text(cveRan
                     ? "No known advisories matched these dependencies (OSV.dev)."
                     : "Turn on CVE in the toolbar and rescan to check these dependencies against OSV.dev.")
                    .font(.callout).foregroundStyle(.secondary)
                    .padding(12)
                Spacer(minLength: 0)
            } else {
                Table(vulnerabilities) {
                    TableColumn("Severity") { SeverityBadge(severity: $0.severity) }.width(80)
                    TableColumn("Advisory") { v in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(v.advisoryId).font(.callout.monospaced()).textSelection(.enabled)
                            if let cve = v.cveAlias {
                                Text(cve).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 140, ideal: 170)
                    TableColumn("Package") { v in
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(v.packageName) \(v.packageVersion)").font(.callout)
                            Text(v.direct ? v.ecosystem : "\(v.ecosystem) · via \(v.resolutionPath)")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .width(min: 120, ideal: 180)
                    TableColumn("CVSS") { v in
                        Text(v.cvssScore.map { String(format: "%.1f", $0) } ?? "—").monospacedDigit()
                    }
                    .width(50)
                    TableColumn("Summary") { v in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(v.summary.isEmpty ? "—" : v.summary).lineLimit(2)
                            if !v.affectedRange.isEmpty {
                                Text(v.affectedRange).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    TableColumn("") { v in
                        if let link = v.references.first.flatMap(URL.init(string:)) {
                            Link(destination: link) { Image(systemName: "arrow.up.right.square") }
                                .help(link.absoluteString)
                        }
                    }
                    .width(24)
                }
            }
        }
    }

    @ViewBuilder private var dependencyPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            paneHeader("Dependencies (\(dependencies.count))", systemImage: "shippingbox")
            Table(dependencies) {
                TableColumn("Package") { d in Text(d.name).textSelection(.enabled) }
                    .width(min: 120, ideal: 180)
                TableColumn("Version") { d in Text(d.version).font(.callout.monospaced()) }
                    .width(min: 70, ideal: 100)
                TableColumn("Ecosystem", value: \.ecosystem).width(80)
                TableColumn("Kind") { d in
                    Text(kind(d)).foregroundStyle(.secondary).lineLimit(1)
                }
                .width(min: 80, ideal: 150)
                TableColumn("Declared in") { d in
                    Text(location(d.file, d.line)).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                if showProvenance {
                    TableColumn("Analyzer") { d in ProvenanceBadge(analyzer: d.sourceAnalyzer) }.width(100)
                }
            }
        }
    }

    private func kind(_ d: Dependency) -> String {
        var parts: [String] = []
        parts.append(d.direct ? "direct" : "transitive")
        if d.dev { parts.append("dev") }
        if d.resolved { parts.append("locked") }
        if let via = d.via, !via.isEmpty { parts.append("via \(via)") }
        return parts.joined(separator: " · ")
    }
}

// MARK: Secrets

/// Secret references and hard-coded literals: name, kind and location only.
/// The model never decodes `evidence_text`, so no source line (redacted or
/// not) can be rendered here.
struct SecretsView: View {
    let scan: Scan?

    private var secrets: [SecretHint] {
        (scan?.secrets ?? []).sorted {
            if $0.isLiteral != $1.isLiteral { return $0.isLiteral }
            return ($0.file, $0.line ?? 0) < ($1.file, $1.line ?? 0)
        }
    }

    private var showProvenance: Bool { secrets.contains { $0.sourceAnalyzer != nil } }

    var body: some View {
        if secrets.isEmpty {
            ContentUnavailableView(
                "No secrets found",
                systemImage: "key",
                description: Text("No secret references or hard-coded credentials were detected."))
        } else {
            VStack(alignment: .leading, spacing: 0) {
                paneHeader("Secrets (\(secrets.count)) — values are never shown", systemImage: "key")
                Table(secrets) {
                    TableColumn("Name") { s in
                        Text(s.name).font(.callout.monospaced()).textSelection(.enabled)
                    }
                    .width(min: 120, ideal: 200)
                    TableColumn("Kind") { s in
                        Label(s.isLiteral ? "Hard-coded · \(WorkflowIssue.humanize(s.kind))" : "Environment reference",
                              systemImage: s.isLiteral ? "exclamationmark.triangle.fill" : "leaf")
                            .foregroundStyle(s.isLiteral ? Color.orange : .secondary)
                            .lineLimit(1)
                    }
                    .width(min: 140, ideal: 220)
                    TableColumn("Location") { s in
                        Text(location(s.file, s.line)).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    TableColumn("Confidence") { s in
                        Text(s.confidence.map { "\(Int(($0 * 100).rounded()))%" } ?? "—").monospacedDigit()
                    }
                    .width(80)
                    if showProvenance {
                        TableColumn("Analyzer") { s in ProvenanceBadge(analyzer: s.sourceAnalyzer) }.width(100)
                    }
                }
            }
        }
    }
}

// MARK: CI workflows

struct WorkflowIssuesView: View {
    let scan: Scan?

    private var issues: [WorkflowIssue] {
        (scan?.workflowIssues ?? []).sorted {
            if $0.severityRank != $1.severityRank { return $0.severityRank > $1.severityRank }
            return ($0.file, $0.line ?? 0) < ($1.file, $1.line ?? 0)
        }
    }

    var body: some View {
        if issues.isEmpty {
            ContentUnavailableView(
                "No CI workflow issues",
                systemImage: "gearshape.2",
                description: Text("No GitHub Actions misconfigurations were found in .github/workflows."))
        } else {
            VStack(alignment: .leading, spacing: 0) {
                paneHeader("GitHub Actions issues (\(issues.count))", systemImage: "gearshape.2")
                Table(issues) {
                    TableColumn("Severity") { SeverityBadge(severity: $0.severity) }.width(80)
                    TableColumn("Issue") { i in Text(i.kindLabel) }.width(min: 140, ideal: 190)
                    TableColumn("Where") { i in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(location(i.file, i.line)).font(.caption.monospaced())
                            if let context = i.context { Text(context).font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                    .width(min: 160, ideal: 240)
                    TableColumn("Evidence") { i in
                        Text(i.evidence ?? "—").font(.caption.monospaced()).lineLimit(2).textSelection(.enabled)
                    }
                }
            }
        }
    }
}

// MARK: Data flows

struct DataFlowsView: View {
    let scan: Scan?

    private var chains: [TaintChain] {
        (scan?.taintChains ?? []).sorted { ($0.confidence ?? 0) > ($1.confidence ?? 0) }
    }

    var body: some View {
        if chains.isEmpty {
            ContentUnavailableView(
                "No data flows",
                systemImage: "arrow.triangle.pull",
                description: Text("No request-to-sink paths were traced in this repository."))
        } else {
            VStack(alignment: .leading, spacing: 0) {
                paneHeader("Route → sink data flows (\(chains.count))", systemImage: "arrow.triangle.pull")
                Table(chains) {
                    TableColumn("Route") { c in
                        Text("\(c.routeMethod) \(c.routePath)").font(.callout.monospaced())
                    }
                    .width(min: 120, ideal: 180)
                    TableColumn("Sink") { c in Text(WorkflowIssue.humanize(c.sinkKind)) }.width(min: 100, ideal: 140)
                    TableColumn("Sink location") { c in
                        Text(location(c.sinkFile, c.sinkLine)).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    TableColumn("Hops") { c in Text("\(c.hops)").monospacedDigit() }.width(40)
                    TableColumn("Confidence") { c in
                        Text(c.confidence.map { "\(Int(($0 * 100).rounded()))%" } ?? "—").monospacedDigit()
                    }
                    .width(80)
                    TableColumn("Notes") { c in
                        Text([c.sanitized ? "sanitized" : nil, c.speculative ? "speculative" : nil]
                            .compactMap { $0 }.joined(separator: " · "))
                            .foregroundStyle(.secondary)
                    }
                    .width(110)
                }
            }
        }
    }
}

// MARK: Analyzers

/// Which analyzers ran, which failed (`scan.analyzer_errors`), what the scan
/// didn't cover (`scan.limitations`), and per-route provenance/auth.
struct AnalyzersView: View {
    let report: Report

    private var errors: [AnalyzerError] { report.scan?.analyzerErrors ?? [] }
    private var limitations: [String] { report.scan?.limitations ?? [] }
    private var routes: [Route] { report.scan?.routes ?? [] }
    private var failedNames: Set<String> { Set(errors.map(\.analyzer)) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if !errors.isEmpty {
                    group("Failed analyzers (\(errors.count))") {
                        ForEach(errors) { e in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(e.analyzer).fontWeight(.medium)
                                    Text(e.message.isEmpty ? e.errorType : "\(e.errorType): \(e.message)")
                                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                        Text("The scan continued without these analyzers, so their signals are missing from this report.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                group("Analyzers run (\(report.analyzersRun.count))") {
                    if report.analyzersRun.isEmpty {
                        Text("This attackmap build doesn't report which analyzers ran.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ForEach(report.analyzersRun) { a in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: failedNames.contains(a.name) ? "xmark.circle.fill" : "checkmark.circle.fill")
                                .foregroundStyle(failedNames.contains(a.name) ? Color.red : .green)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(a.name).font(.callout.monospaced()).fontWeight(.medium)
                                    if !a.ecosystems.isEmpty {
                                        Text(a.ecosystems.joined(separator: ", "))
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                if let description = a.description, !description.isEmpty {
                                    Text(description).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }

                if !limitations.isEmpty {
                    group("Not analyzed") {
                        ForEach(limitations, id: \.self) { item in
                            Label(item, systemImage: "exclamationmark.triangle")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }
                }

                if !routes.isEmpty {
                    group("Routes (\(routes.count))") {
                        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                            GridRow {
                                Text("Route"); Text("Auth"); Text("Location"); Text("Analyzer")
                            }
                            .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            ForEach(routes) { r in
                                GridRow {
                                    Text("\(r.method) \(r.path)").font(.callout.monospaced())
                                    Text(authLabel(r))
                                        .foregroundStyle(r.auth == "anonymous" ? Color.orange : r.auth == "required" ? .green : .secondary)
                                        .help(r.guards.joined(separator: ", "))
                                    Text(location(r.file, r.line)).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    ProvenanceBadge(analyzer: r.sourceAnalyzer)
                                }
                            }
                        }
                        if !routes.contains(where: { $0.sourceAnalyzer != nil }) {
                            Text("Per-signal analyzer provenance isn't included in this engine's report.")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func authLabel(_ r: Route) -> String {
        switch r.auth {
        case "required": return r.guards.isEmpty ? "required" : "required (\(r.guards.joined(separator: ", ")))"
        case "anonymous": return "anonymous"
        default: return "unknown"
        }
    }

    private func group(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased()).font(.caption.weight(.bold)).foregroundStyle(.secondary)
            content()
        }
    }
}

@MainActor
private func paneHeader(_ title: String, systemImage: String) -> some View {
    HStack {
        Label(title, systemImage: systemImage).font(.callout.weight(.semibold))
        Spacer()
    }
    .padding(.horizontal, 12).padding(.vertical, 8)
}
