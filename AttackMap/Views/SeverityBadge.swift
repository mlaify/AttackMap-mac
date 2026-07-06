import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        case .info: return .blue
        case .unknown: return .secondary
        }
    }

    var label: String {
        switch self {
        case .unknown: return "—"
        default: return rawValue.capitalized
        }
    }
}

/// A small filled pill for a severity string.
struct SeverityBadge: View {
    let severity: String

    private var sev: Severity { Severity(severity) }

    var body: some View {
        Text(sev.label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(sev.color.opacity(0.18), in: Capsule())
            .foregroundStyle(sev.color)
    }
}
