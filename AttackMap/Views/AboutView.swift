import SwiftUI

/// Custom About window: the brand mark, version, the resolved CLI, and links.
struct AboutView: View {
    @Environment(\.openWindow) private var openWindow

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }
    private var build: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""
    }
    private var cliPath: String? {
        let override = UserDefaults.standard.string(forKey: "cliPathOverride")
        return CLILocator.locate(explicitPath: override)?.path
    }

    var body: some View {
        VStack(spacing: 12) {
            BrandMark(size: 88)

            Text("AttackMap")
                .font(.system(size: 24, weight: .semibold))

            Text("Native macOS front-end for the AttackMap security analyzer")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text(build.isEmpty ? "Version \(version)" : "Version \(version) (\(build))")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Divider().padding(.horizontal, 32)

            HStack(spacing: 6) {
                Image(systemName: cliPath == nil ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                    .foregroundStyle(cliPath == nil ? Color.orange : Color.green)
                Text(cliPath.map { "attackmap CLI · \($0)" }
                     ?? "attackmap CLI not found — set its path in Settings")
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .font(.caption)

            HStack(spacing: 18) {
                Link("Docs", destination: URL(string: "https://docs.matthewd.xyz")!)
                Link("App repo", destination: URL(string: "https://github.com/mlaify/AttackMap-mac")!)
                Link("Engine repo", destination: URL(string: "https://github.com/mlaify/AttackMap")!)
                Button("Help") { openWindow(id: "help") }
                    .buttonStyle(.link)
            }
            .font(.callout)

            Text("© 2026 mlaify · MIT-licensed")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(28)
        .frame(width: 400)
    }
}
