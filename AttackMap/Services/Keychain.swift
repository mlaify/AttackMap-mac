import Foundation
import Security

/// Minimal generic-password Keychain wrapper for the Anthropic API key. The key
/// is passed to `attackmap` via the environment only when an LLM mode runs.
enum Keychain {
    static let anthropicAPIKey = "ANTHROPIC_API_KEY"
    private static let service = "io.mlaify.AttackMap"

    private static func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Store (or, when `value` is nil/empty, delete) a secret.
    static func set(_ value: String?, account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
        guard let value, !value.isEmpty, let data = value.data(using: .utf8) else { return }
        var add = baseQuery(account)
        add[kSecValueData as String] = data
        SecItemAdd(add as CFDictionary, nil)
    }

    static func get(account: String) -> String? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
