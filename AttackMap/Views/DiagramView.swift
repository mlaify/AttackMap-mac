import SwiftUI
import WebKit

/// Renders the scan's attack-path and topology Mermaid diagrams in a WKWebView
/// using the bundled (offline) mermaid.js.
struct DiagramView: View {
    let outputDirectory: URL?
    /// Markdown artifacts to pull ```mermaid blocks from. Defaults to the
    /// single-repo path/topology diagrams; the fleet view passes fleet-graph.md.
    var filenames: [String] = ["attackmap-paths.md", "attackmap-topology.md"]
    @State private var html: String?
    @State private var isEmpty = true

    var body: some View {
        Group {
            if let html, !isEmpty {
                MermaidWebView(html: html)
            } else {
                ContentUnavailableView(
                    "No diagrams",
                    systemImage: "flowchart",
                    description: Text("Attack-path and topology diagrams appear here after a scan."))
            }
        }
        .task(id: outputDirectory?.path) { rebuild() }
    }

    private func rebuild() {
        guard let dir = outputDirectory else { html = nil; isEmpty = true; return }
        var diagrams: [MermaidExtractor.Diagram] = []
        for name in filenames {
            let url = dir.appendingPathComponent(name)
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                diagrams += MermaidExtractor.diagrams(fromMarkdown: text)
            }
        }
        isEmpty = diagrams.isEmpty
        html = diagrams.isEmpty ? nil : DiagramHTML.page(diagrams: diagrams)
    }
}

/// Builds a self-contained HTML page with mermaid.js inlined from the bundle.
enum DiagramHTML {
    static func page(diagrams: [MermaidExtractor.Diagram]) -> String {
        let mermaidJS = Bundle.main.url(forResource: "mermaid.min", withExtension: "js")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
        let blocks = diagrams.map {
            "<h2>\(escape($0.title))</h2>\n<pre class=\"mermaid\">\(escape($0.code))</pre>"
        }.joined(separator: "\n")
        return """
        <!doctype html><html><head><meta charset="utf-8">
        <style>
          :root { color-scheme: light dark; }
          body { font: 13px -apple-system, system-ui, sans-serif; margin: 16px; background: transparent; }
          h2 { font-size: 13px; color: #888; font-weight: 600; margin: 20px 0 6px; }
          .mermaid { margin-bottom: 24px; }
        </style>
        <script>\(mermaidJS)</script>
        </head><body>
        \(blocks)
        <script>
          try { mermaid.initialize({ startOnLoad: true, theme: 'neutral', securityLevel: 'strict' }); }
          catch (e) { document.body.insertAdjacentText('afterbegin', 'mermaid failed to load'); }
        </script>
        </body></html>
        """
    }

    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}

private struct MermaidWebView: NSViewRepresentable {
    let html: String

    func makeNSView(context: Context) -> WKWebView {
        WKWebView()
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        webView.loadHTMLString(html, baseURL: nil)
    }
}
