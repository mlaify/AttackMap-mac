import SwiftUI

/// Composed attack chains, most likely first: each chain runs from what an
/// outside attacker starts with to an impact, one cited finding per step.
struct AttackChainsView: View {
    let report: Report

    private var chains: [AttackChain] {
        report.attackChains.sorted { $0.likelihood > $1.likelihood }
    }

    var body: some View {
        if chains.isEmpty {
            ContentUnavailableView(
                "No attack chains",
                systemImage: "link",
                description: Text("No combination of findings forms a multi-step chain."))
        } else {
            List {
                ForEach(chains) { chain in
                    Section {
                        ForEach(Array(chain.steps.enumerated()), id: \.offset) { index, step in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("\(index + 1)")
                                    .font(.caption.monospaced().weight(.bold))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 18, alignment: .trailing)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(step.title).textSelection(.enabled)
                                    HStack(spacing: 6) {
                                        Text(step.ruleId).font(.caption.monospaced())
                                        if let place = step.place {
                                            Text(place).font(.caption.monospaced()).foregroundStyle(.secondary)
                                        }
                                        Text("→ " + step.grants.map(AttackChain.label).joined(separator: ", "))
                                            .font(.caption).foregroundStyle(.orange)
                                    }
                                    ForEach(step.preconditionNotes, id: \.self) { note in
                                        Text("Assumes: \(note)").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .accessibilityIdentifier("chainStep")
                        }
                    } header: {
                        HStack {
                            Text(AttackChain.label(chain.impact)).font(.headline)
                            Text("from " + chain.start.map(AttackChain.label).joined(separator: ", "))
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text(String(format: "likelihood %.2f", chain.likelihood))
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .accessibilityIdentifier("chainsList")
        }
    }
}
