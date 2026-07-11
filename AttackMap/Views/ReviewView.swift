import SwiftUI

/// Renders the engine's defensive-review markdown. Uses AttributedString's
/// markdown parser (inline styling, whitespace preserved); good enough for the
/// review prose without pulling in a full markdown engine.
struct ReviewView: View {
    let report: Report

    var body: some View {
        if let markdown = report.defensiveReviewMarkdown, !markdown.isEmpty {
            ScrollView {
                MarkdownText(markdown: markdown).padding(20)
            }
        } else {
            ContentUnavailableView(
                "No review",
                systemImage: "doc.text",
                description: Text("The defensive review is only generated in the full report."))
        }
    }
}
