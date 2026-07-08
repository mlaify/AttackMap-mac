import SwiftUI

/// Renders the engine's defensive-review markdown. Uses AttributedString's
/// markdown parser (inline styling, whitespace preserved); good enough for the
/// review prose without pulling in a full markdown engine.
struct ReviewView: View {
    let report: Report

    var body: some View {
        if let markdown = report.defensiveReviewMarkdown, !markdown.isEmpty {
            ScrollView {
                Text(attributed(markdown))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
            }
        } else {
            ContentUnavailableView(
                "No review",
                systemImage: "doc.text",
                description: Text("The defensive review is only generated in the full report."))
        }
    }

    private func attributed(_ markdown: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(
            interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: markdown, options: options))
            ?? AttributedString(markdown)
    }
}
