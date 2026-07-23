import AppKit
import UniformTypeIdentifiers

/// Thin wrapper around `NSOpenPanel`. We use AppKit's panel directly rather than
/// SwiftUI's `.fileImporter` because stacking more than one `.fileImporter` on a
/// single view is unreliable (only one presents), and the panel gives us folder
/// + multi-selection with no sandbox entitlement (this app is not sandboxed).
@MainActor
enum FolderPicker {
    /// Choose one or more directories. Returns `[]` if the user cancels.
    static func chooseDirectories(allowMultiple: Bool = true) -> [URL] {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = allowMultiple
        panel.resolvesAliases = true
        panel.prompt = "Scan"
        panel.message = allowMultiple
            ? "Choose a repository — or select several for a cross-repo fleet scan."
            : "Choose a repository."
        return panel.runModal() == .OK ? panel.urls : []
    }

    /// Choose a single file (optionally constrained by content type). Returns
    /// `nil` if the user cancels.
    static func chooseFile(contentTypes: [UTType] = []) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        if !contentTypes.isEmpty { panel.allowedContentTypes = contentTypes }
        return panel.runModal() == .OK ? panel.url : nil
    }
}
