import SwiftUI

/// In-app help. Task-oriented sections describing the real controls and how to
/// resolve the common snags (missing CLI, no LLM output, version-gated options).
struct HelpView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 12) {
                    BrandMark(size: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("AttackMap help").font(.title2).fontWeight(.semibold)
                        Text("A launcher + viewer for the attackmap CLI.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }

                section("Getting started", [
                    "Click **Choose repo…** and pick a project folder.",
                    "Press **Run scan** (⌘↩). Live progress shows in the strip below the toolbar.",
                    "When it finishes, browse the results in the sidebar sections.",
                ])

                section("Scan options", [
                    "**CVE** — cross-reference the project's dependencies against OSV.dev.",
                    "**Analyzers** — *Automatic* lets the engine pick analyzers by language, or pin specific modules. (Requires the CLI ≥ 0.4.4.)",
                    "**LLM** — None, Review, Hunt, Hunt + verify, or Remediate. Choosing one reveals the provider/model row.",
                    "**Watch** — auto re-scan on file changes; the badge shows new vs. resolved findings.",
                ])

                section("LLM providers & keys", [
                    "**Provider** — Claude or OpenAI / Codex, each with a Model and Reasoning picker.",
                    "**Fast** — ~2.5× faster output; Claude Opus 4.8/4.7 only.",
                    "Backends resolve automatically: Claude uses `ANTHROPIC_API_KEY` or the `claude` CLI; OpenAI uses `OPENAI_API_KEY` or the `codex` CLI.",
                    "Set API keys in **Settings** (⌘,) — they're stored in your login Keychain and passed only when an LLM mode runs.",
                    "OpenAI needs the CLI ≥ 0.4.3; Fast needs ≥ 0.4.3.",
                ])

                section("Reading results", [
                    "**Overview** — totals, severity breakdown, most-exploitable finding.",
                    "**Findings / Exploitability / Attack paths / Attack surface** — the structured report.",
                    "**Diagrams** — rendered Mermaid attack-path / topology graphs.",
                    "**Review / AI Review** — the heuristic and LLM narratives (the latter needs an LLM run).",
                ])

                section("Requirements & updating", [
                    "AttackMap drives the **`attackmap` CLI** — install it with `brew install mlaify/tap/attackmap`.",
                    "Update everything together: `brew upgrade --cask attackmap-app` (the app depends on the CLI formula).",
                ])

                section("Troubleshooting", [
                    "**\"attackmap not found\"** — install via Homebrew, or set the binary's path in Settings.",
                    "**An LLM mode produced no output** — add an API key in Settings, or make sure `claude` / `codex` is on your PATH.",
                    "**An option is greyed out or says \"update to ≥ x\"** — run `brew upgrade attackmap`; the app enables features as the CLI supports them.",
                ])

                HStack(spacing: 18) {
                    Link("Documentation", destination: URL(string: "https://github.com/mlaify/AttackMap#readme")!)
                    Link("Report an issue", destination: URL(string: "https://github.com/mlaify/AttackMap-mac/issues")!)
                }
                .font(.callout)
                .padding(.top, 4)
            }
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 560, height: 640)
    }

    private func section(_ title: String, _ points: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            ForEach(points, id: \.self) { point in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("•").foregroundStyle(.secondary)
                    Text(.init(point))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.callout)
            }
        }
    }
}
