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
                        note = Self.save(apiKey, account: Keychain.anthropicAPIKey)
                    }
                    Button("Clear") {
                        apiKey = ""
                        note = Self.save(nil, account: Keychain.anthropicAPIKey)
                    }
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
                Text("Used for the Claude provider (API backend). Passed to attackmap only when an LLM mode is selected. Stored in the Keychain, never in a file. Every analyzer plugin the CLI loads can read it while an LLM mode runs.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("OpenAI API key") {
                SecureField("sk-…", text: $openAIKey)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    Button("Save to Keychain") {
                        openAINote = Self.save(openAIKey, account: Keychain.openAIAPIKey)
                    }
                    Button("Clear") {
                        openAIKey = ""
                        openAINote = Self.save(nil, account: Keychain.openAIAPIKey)
                    }
                    Text(openAINote).font(.caption).foregroundStyle(.secondary)
                }
                Text("Used for the OpenAI provider (API backend). Not needed if you sign in with the `codex` CLI. Stored in the Keychain, never in a file. Every analyzer plugin the CLI loads can read it while an LLM mode runs.")
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

    /// Save or clear a key and describe the outcome; failures are shown, not
    /// swallowed (#8).
    static func save(_ value: String?, account: String) -> String {
        do {
            switch try Keychain.set(value, account: account) {
            case nil: return "Cleared."
            case .dataProtection?: return "Saved."
            case .legacy?: return "Saved (login keychain)."
            }
        } catch {
            return (error as? LocalizedError)?.errorDescription ?? "Couldn't save to the Keychain."
        }
    }

    private var detected: Bool { CLILocator.cachedLocate(explicitPath: cliPath) != nil }

    private var detectionStatus: String {
        if let url = CLILocator.cachedLocate(explicitPath: cliPath) { return "Using: \(url.path)" }
        return "attackmap not found — install via `brew install mlaify/tap/attackmap`."
    }
}
