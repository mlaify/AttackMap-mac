import SwiftUI

/// Menu commands: a custom About window (with the brand mark) replacing the
/// default one, and a Help item (⌘?) that opens the in-app help window.
struct AttackMapCommands: Commands {
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About AttackMap") { openWindow(id: "about") }
        }
        CommandGroup(replacing: .help) {
            Button("AttackMap Help") { openWindow(id: "help") }
                .keyboardShortcut("?", modifiers: .command)
        }
    }
}
