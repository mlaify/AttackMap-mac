import AppKit
import UniformTypeIdentifiers

/// Export / open / reveal for the report artifacts the engine wrote.
@MainActor
enum ReportExporter {
    /// SARIF has no system UTI; fall back to JSON (SARIF is JSON).
    static var sarifType: UTType { UTType(filenameExtension: "sarif", conformingTo: .json) ?? .json }
    static var markdownType: UTType { UTType(filenameExtension: "md", conformingTo: .plainText) ?? .plainText }

    /// Ask where to save a copy of `source`, then copy it there (replacing an
    /// existing file the user agreed to overwrite in the panel). Returns the
    /// destination, or nil if cancelled. Throws if the copy fails.
    @discardableResult
    static func saveCopy(of source: URL, suggestedName: String, contentType: UTType) throws -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [contentType]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let destination = panel.url else { return nil }
        try copy(source, to: destination)
        return destination
    }

    /// Copy, replacing `destination` if present. Internal for tests.
    nonisolated static func copy(_ source: URL, to destination: URL,
                                 fileManager: FileManager = .default) throws {
        if source.standardizedFileURL == destination.standardizedFileURL { return }
        if fileManager.fileExists(atPath: destination.path) {
            _ = try fileManager.replaceItemAt(destination, withItemAt: try stagedCopy(of: source, fileManager: fileManager))
        } else {
            try fileManager.copyItem(at: source, to: destination)
        }
    }

    /// A temp copy to swap in atomically with `replaceItemAt`.
    nonisolated private static func stagedCopy(of source: URL, fileManager: FileManager) throws -> URL {
        let staged = fileManager.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension(source.pathExtension)
        try fileManager.copyItem(at: source, to: staged)
        return staged
    }

    /// Open in the user's default handler for the file type (e.g. VS Code's
    /// SARIF viewer, Xcode). With no handler registered, reveal in Finder so
    /// the user can pick one via "Open With".
    static func openInDefaultApp(_ url: URL) {
        if NSWorkspace.shared.urlForApplication(toOpen: url) != nil {
            NSWorkspace.shared.open(url)
        } else {
            reveal(url)
        }
    }

    static func reveal(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
