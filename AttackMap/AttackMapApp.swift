import SwiftUI

@main
struct AttackMapApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 900, minHeight: 560)
        }
        .windowStyle(.titleBar)

        Settings {
            SettingsView()
        }
    }
}
