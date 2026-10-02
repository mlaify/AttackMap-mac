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
                    "**Baseline** — diff against the previous scan of this repo (default), a report you choose, or none; see the **Diff** tab. *Fail on new HIGH findings* flags a run that adds them.",
                    "**Generate PR comment** — also write the Markdown PR summary (save or copy it from **Export**).",
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
                    "**Diff** — what changed vs. the baseline: new, resolved, and newly suppressed findings.",
                    "**Dependencies** — manifest/lockfile dependencies, plus known CVEs after a **CVE** scan.",
                    "**Secrets** — secret references and hard-coded literals by name, kind and location (values are never shown).",
                    "**CI workflows / Data flows** — GitHub Actions misconfigurations and route → sink taint chains.",
                    "**Analyzers** — which analyzers ran or failed, what wasn't analyzed, and route auth/provenance.",
                    "**Diagrams** — rendered Mermaid attack-path / topology graphs.",
                    "**Review / AI Review** — the heuristic and LLM narratives (the latter needs an LLM run).",
                ])

                section("Exporting & suppressing", [
                    "**Export** (status strip) — save the SARIF, report JSON, or PR comment; open SARIF/JSON in your default app; or reveal it in Finder.",
                    "**Suppress…** (finding detail) — appends a rule with your reason (and optional expiry, owner, ticket) to the repo's `.attackmap-suppress.yaml`, creating it if needed. The target file is shown before anything is written.",
                    "Rescan after suppressing — the finding moves to the **Suppressed** list under Findings (unless *Ignore all suppressions* is on).",
                ])

                section("Requirements & updating", [
                    "AttackMap drives the **`attackmap` CLI** — install it with `brew install mlaify/tap/attackmap` (or `pipx install git+https://github.com/mlaify/AttackMap.git`).",
                    "Update both with `brew upgrade attackmap attackmap-app` (pipx installs: `pipx upgrade attackmap`), or download the latest DMG from GitHub Releases.",
                ])

                section("Troubleshooting", [
                    "**\"attackmap not found\"** — install it with `brew install mlaify/tap/attackmap`, or set the binary's path in Settings.",
                    "**An LLM mode produced no output** — add an API key in Settings, or make sure `claude` / `codex` is on your PATH.",
                    "**An option is greyed out or says \"update to ≥ x\"** — run `brew upgrade attackmap`; the app enables features as the CLI supports them.",
                ])

                HStack(spacing: 18) {
                    Link("Documentation", destination: URL(string: "https://docs.mlaify.io/gui/")!)
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
