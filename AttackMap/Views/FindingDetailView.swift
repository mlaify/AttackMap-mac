import SwiftUI

/// Full detail for one finding: severity/confidence, exploitability, evidence
/// (which typically carries `file:line`), ATT&CK techniques, tags, and the
/// suggested mitigation.
struct FindingDetailView: View {
    let finding: Finding

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if !finding.evidence.isEmpty { section("Evidence", evidence) }
                if !finding.attackTechniques.isEmpty { section("ATT&CK techniques", techniques) }
                if let mitigation = finding.mitigation, !mitigation.isEmpty {
                    section("Mitigation", Text(mitigation).textSelection(.enabled))
                }
                if !finding.tags.isEmpty { section("Tags", tags) }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(finding.title).font(.title2.weight(.semibold)).textSelection(.enabled)
            HStack(spacing: 8) {
                SeverityBadge(severity: finding.severity)
                metaPill("confidence \(finding.confidence)")
                if let tier = finding.exploitabilityTier {
                    metaPill("exploitability \(tier)")
                }
                if let score = finding.exploitability {
                    metaPill("score \(score)").monospacedDigit()
                }
            }
        }
    }

    private var evidence: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(finding.evidence.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var techniques: some View {
        FlowText(finding.attackTechniques.map { "🎯 \($0)" })
    }

    private var tags: some View {
        FlowText(finding.tags)
    }

    private func metaPill(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(.quaternary, in: Capsule())
            .foregroundStyle(.secondary)
    }

    private func section(_ title: String, _ content: some View) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.caption.weight(.bold)).foregroundStyle(.secondary)
            content
        }
    }
}

/// Simple wrapping row of chips.
private struct FlowText: View {
    let items: [String]
    init(_ items: [String]) { self.items = items }

    var body: some View {
        WrapHStack(items, id: \.self) { item in
            Text(item)
                .font(.caption)
                .padding(.horizontal, 7).padding(.vertical, 2)
                .background(.quaternary, in: Capsule())
        }
    }
}

/// Minimal flow layout so chips wrap instead of clipping.
private struct WrapHStack<Data: RandomAccessCollection, Content: View>: View where Data.Element: Hashable {
    let data: Data
    let content: (Data.Element) -> Content
    init(_ data: Data, id: KeyPath<Data.Element, Data.Element> = \.self,
         @ViewBuilder content: @escaping (Data.Element) -> Content) {
        self.data = data
        self.content = content
    }

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(Array(data), id: \.self) { content($0) }
        }
    }
}

/// A tiny Layout that lays children left-to-right and wraps to new lines.
private struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0; y += rowHeight + spacing; rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxWidth == .infinity ? x : maxWidth, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX; y += rowHeight + spacing; rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
