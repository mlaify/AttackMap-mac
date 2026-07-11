import SwiftUI

/// Renders markdown via AttributedString (inline styling, whitespace
/// preserved) — good enough for the engine's review/hunt/remediation prose
/// without a full markdown engine. Shared by ReviewView and AIReviewView.
struct MarkdownText: View {
    let markdown: String

    var body: some View {
        Text(attributed)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var attributed: AttributedString {
        let options = AttributedString.MarkdownParsingOptions(
            interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: markdown, options: options))
            ?? AttributedString(markdown)
    }
}
