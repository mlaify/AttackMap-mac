import Foundation

/// One model the user's credentials can use, as `attackmap llm-models --json`
/// reports it (attackmap ≥ 1.1). `source == "account"` means the provider listed
/// it for these credentials; `"catalog"` means AttackMap's built-in list (the
/// `claude` CLI has no model list), so a gated model there may not be on the account.
struct LLMModelOption: Decodable, Identifiable, Hashable {
    let id: String
    let displayName: String
    let provider: String
    let source: String
    let isDefault: Bool
    /// Set for models only some accounts can use, e.g. Claude Mythos (verified organizations).
    let gated: String?
    let efforts: [String]
    let fast: Bool
    /// OpenAI/Codex access programs, e.g. ["cyber": ["standard", "daybreak_blue"]].
    let accessPrograms: [String: [String]]
    let deprecated: Bool

    enum CodingKeys: String, CodingKey {
        case id, provider, source, gated, efforts, fast, deprecated
        case displayName = "display_name"
        case isDefault = "default"
        case accessPrograms = "access_programs"
    }

    init(id: String, displayName: String, provider: String, source: String = "catalog",
         isDefault: Bool = false, gated: String? = nil, efforts: [String] = [],
         fast: Bool = false, accessPrograms: [String: [String]] = [:], deprecated: Bool = false) {
        self.id = id
        self.displayName = displayName
        self.provider = provider
        self.source = source
        self.isDefault = isDefault
        self.gated = gated
        self.efforts = efforts
        self.fast = fast
        self.accessPrograms = accessPrograms
        self.deprecated = deprecated
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        displayName = (try? c.decode(String.self, forKey: .displayName)) ?? id
        provider = (try? c.decode(String.self, forKey: .provider)) ?? ""
        source = (try? c.decode(String.self, forKey: .source)) ?? "account"
        isDefault = (try? c.decode(Bool.self, forKey: .isDefault)) ?? false
        gated = try? c.decode(String.self, forKey: .gated)
        efforts = (try? c.decode([String].self, forKey: .efforts)) ?? []
        fast = (try? c.decode(Bool.self, forKey: .fast)) ?? false
        accessPrograms = (try? c.decode([String: [String]].self, forKey: .accessPrograms)) ?? [:]
        deprecated = (try? c.decode(Bool.self, forKey: .deprecated)) ?? false
    }

    /// Cyber access programs the model offers on this account (Codex), e.g. daybreak_blue.
    var cyberPrograms: [String] { accessPrograms["cyber"] ?? [] }

    /// Picker label: the name plus what the user should know before choosing it.
    var label: String {
        var tags: [String] = []
        if isDefault { tags.append("default") }
        if gated != nil { tags.append(source == "account" ? "verified access" : "verified orgs only") }
        if cyberPrograms.contains(where: { $0.hasPrefix("daybreak") }) { tags.append("Daybreak") }
        if deprecated { tags.append("deprecated") }
        return tags.isEmpty ? displayName : "\(displayName) (\(tags.joined(separator: ", ")))"
    }
}

/// The `attackmap llm-models --json` document.
struct LLMModelList: Decodable {
    let provider: String
    let backend: String?
    let note: String?
    let error: String?
    let models: [LLMModelOption]
}

enum LLMModelCatalog {
    /// The models the user's credentials can use for `provider` (claude, openai,
    /// local), through the same environment a scan gets (login-shell PATH for the
    /// `claude` / `codex` CLIs, the API key from Settings). nil when the CLI
    /// couldn't run; a list with `error` set when the provider couldn't be read.
    static func load(executable: URL, provider: String, environment: [String: String],
                     baseURL: String? = nil) -> LLMModelList? {
        var args = ["llm-models", "--llm-provider", provider, "--json"]
        if provider == "local", let baseURL, !baseURL.isEmpty { args += ["--llm-base-url", baseURL] }
        guard let out = ShellRunner.run(executable, args, environment: environment, timeout: 90) else { return nil }
        return decode(out.stdout)
    }

    static func decode(_ data: Data) -> LLMModelList? {
        try? JSONDecoder().decode(LLMModelList.self, from: data)
    }

    /// Used when the installed CLI predates `llm-models` (< 1.1): the Claude models
    /// it can call by ID. OpenAI then offers only the account default.
    static let claudePresets: [LLMModelOption] = [
        .init(id: "claude-opus-5-5", displayName: "Claude Opus 5.5", provider: "claude", isDefault: true, fast: true),
        .init(id: "claude-fable-5-2", displayName: "Claude Fable 5.2", provider: "claude", fast: true),
        .init(id: "claude-mythos-5-2", displayName: "Claude Mythos 5.2", provider: "claude",
              gated: "verified organizations only", fast: true),
        .init(id: "claude-sonnet-5-5", displayName: "Claude Sonnet 5.5", provider: "claude"),
        .init(id: "claude-haiku-5-5", displayName: "Claude Haiku 5.5", provider: "claude"),
        .init(id: "claude-opus-4-8", displayName: "Claude Opus 4.8", provider: "claude"),
    ]

    /// Fast mode by model ID, for models the list didn't describe (custom IDs, older CLIs).
    static let fastCapableIDs: Set<String> = ["claude-opus-5-5", "claude-fable-5-2", "claude-mythos-5-2", "claude-opus-5"]
}
