import Foundation

/// Pulls titled ```mermaid blocks out of AttackMap's diagram markdown
/// (`attackmap-paths.md`, `attackmap-topology.md`).
enum MermaidExtractor {
    struct Diagram: Identifiable, Hashable {
        let id = UUID()
        let title: String
        let code: String
    }

    static func diagrams(fromMarkdown markdown: String) -> [Diagram] {
        var result: [Diagram] = []
        var heading = "Diagram"
        var inFence = false
        var buffer: [String] = []

        for line in markdown.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if !inFence, trimmed.hasPrefix("#") {
                heading = cleanHeading(trimmed)
            } else if !inFence, trimmed == "```mermaid" {
                inFence = true
                buffer = []
            } else if inFence, trimmed == "```" {
                inFence = false
                let code = buffer.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
                if !code.isEmpty { result.append(Diagram(title: heading, code: code)) }
            } else if inFence {
                buffer.append(line)
            }
        }
        return result
    }

    /// Strip leading `#`s and an optional `"N. "` ordinal from a heading.
    private static func cleanHeading(_ line: String) -> String {
        var text = line.drop(while: { $0 == "#" }).trimmingCharacters(in: .whitespaces)
        if let dot = text.firstIndex(of: "."),
           text[text.startIndex..<dot].allSatisfy(\.isNumber),
           dot != text.startIndex {
            text = String(text[text.index(after: dot)...]).trimmingCharacters(in: .whitespaces)
        }
        return text.isEmpty ? "Diagram" : text
    }
}
