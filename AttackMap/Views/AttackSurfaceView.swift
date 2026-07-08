import SwiftUI

/// The classified attack surface: every detected route with its category,
/// exposure, risk tier, and auth signals.
struct AttackSurfaceView: View {
    let report: Report

    private var surfaces: [AttackSurface] {
        report.attackSurfaces.sorted { Severity($0.risk).rank > Severity($1.risk).rank }
    }

    var body: some View {
        if surfaces.isEmpty {
            ContentUnavailableView(
                "No routes classified",
                systemImage: "point.topleft.down.to.point.bottomright.curvepath",
                description: Text("No web routes were detected in this repository."))
        } else {
            Table(surfaces) {
                TableColumn("Method") { Text($0.method).font(.caption.monospaced()) }
                    .width(64)
                TableColumn("Route", value: \.route)
                TableColumn("Category", value: \.category).width(120)
                TableColumn("Exposure", value: \.exposure).width(90)
                TableColumn("Risk") { surface in
                    Text(surface.risk.capitalized).foregroundStyle(Severity(surface.risk).color)
                }
                .width(70)
                TableColumn("Auth") { surface in
                    Text(surface.authSignals.isEmpty ? "—" : surface.authSignals.joined(separator: ", "))
                        .foregroundStyle(surface.authSignals.isEmpty ? .secondary : .primary)
                }
                .width(140)
            }
        }
    }
}
