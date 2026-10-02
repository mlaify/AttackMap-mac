import SwiftUI

/// Preferences: pin the `attackmap` CLI path and store the LLM API keys
/// (used only when an LLM mode runs, and only the one matching the provider).
struct SettingsView: View {
    @AppStorage("cliPathOverride") private var cliPath = ""
    @State private var apiKey = ""
    @State private var note = ""
    @State private var openAIKey = ""
    @State private var openAINote = ""

    var body: some View {
        Form {
            Section("attackmap CLI") {
                TextField("Path (blank = auto-detect)", text: $cliPath)
                    .textFieldStyle(.roundedBorder)
                Text(detectionStatus)
                    .font(.caption)
                    .foregroundStyle(detected ? Color.secondary : .red)
            }

            Section("Anthropic API key") {
                SecureField("sk-ant-…", text: $apiKey)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    Button("Save to Keychain") {
                        Keychain.set(apiKey, account: Keychain.anthropicAPIKey)
                        note = "Saved."
                    }
                    Button("Clear") {
                        apiKey = ""
                        Keychain.set(nil, account: Keychain.anthropicAPIKey)
                        note = "Cleared."
                    }
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
                Text("Used for the Claude provider (API backend). Passed to attackmap only when an LLM mode is selected. Stored in your login Keychain, never on disk.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("OpenAI API key") {
                SecureField("sk-…", text: $openAIKey)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    Button("Save to Keychain") {
                        Keychain.set(openAIKey, account: Keychain.openAIAPIKey)
                        openAINote = "Saved."
                    }
                    Button("Clear") {
                        openAIKey = ""
                        Keychain.set(nil, account: Keychain.openAIAPIKey)
                        openAINote = "Cleared."
                    }
                    Text(openAINote).font(.caption).foregroundStyle(.secondary)
                }
                Text("Used for the OpenAI provider (API backend). Not needed if you sign in with the `codex` CLI. Stored in your login Keychain, never on disk.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .onAppear {
            apiKey = Keychain.get(account: Keychain.anthropicAPIKey) ?? ""
            openAIKey = Keychain.get(account: Keychain.openAIAPIKey) ?? ""
        }
    }

    private var detected: Bool { CLILocator.locate(explicitPath: cliPath) != nil }

    private var detectionStatus: String {
        if let url = CLILocator.locate(explicitPath: cliPath) { return "Using: \(url.path)" }
        return "attackmap not found — install via `brew install mlaify/tap/attackmap`."
    }
}
