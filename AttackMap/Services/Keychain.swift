import Foundation
import Security

/// The SecItem calls the keychain wrapper needs, so tests can substitute a
/// mock (#8).
protocol SecItemAPI: Sendable {
    func add(_ attributes: [String: Any]) -> OSStatus
    func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus
    func copyMatching(_ query: [String: Any]) -> (OSStatus, AnyObject?)
    func delete(_ query: [String: Any]) -> OSStatus
}

struct LiveSecItemAPI: SecItemAPI {
    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    func copyMatching(_ query: [String: Any]) -> (OSStatus, AnyObject?) {
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

struct KeychainError: Error, LocalizedError, Equatable {
    let status: OSStatus

    var errorDescription: String? {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return "Couldn't save to the Keychain: \(message)"
    }
}

/// Generic-password Keychain wrapper for the LLM API keys. A key is passed to
/// `attackmap` via the environment only when an LLM mode runs, and only the one
/// matching the selected provider — note that every analyzer plugin the CLI
/// loads can read that environment.
///
/// Items go to the data-protection keychain (`kSecUseDataProtectionKeychain`,
/// accessible only when unlocked, this device only) when the build is entitled
/// to it. Unsigned dev/test builds, and signed builds without a
/// keychain-access-groups entitlement, get `errSecMissingEntitlement`; those
/// fall back to the legacy file-based keychain. A key found only in the legacy
/// keychain is migrated on read when the data-protection keychain is usable.
struct Keychain: Sendable {
    static let anthropicAPIKey = "ANTHROPIC_API_KEY"
    static let openAIAPIKey = "OPENAI_API_KEY"
    static let shared = Keychain()

    enum Store: Equatable { case dataProtection, legacy }

    private let service: String
    private let api: SecItemAPI

    init(service: String = "io.mlaify.AttackMap", api: SecItemAPI = LiveSecItemAPI()) {
        self.service = service
        self.api = api
    }

    // MARK: Static conveniences used by the app

    /// Store a secret, or delete it when `value` is nil/empty. Throws on failure
    /// so Settings can tell the user (the old delete-then-add lost the key when
    /// the add failed).
    @discardableResult
    static func set(_ value: String?, account: String) throws -> Store? {
        try shared.set(value, account: account)
    }

    static func get(account: String) -> String? {
        shared.get(account: account)
    }

    // MARK: Implementation

    private func query(_ account: String, store: Store) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if store == .dataProtection {
            q[kSecUseDataProtectionKeychain as String] = true
        }
        return q
    }

    /// Returns the store the value was written to (nil for a delete).
    @discardableResult
    func set(_ value: String?, account: String) throws -> Store? {
        guard let value, !value.isEmpty, let data = value.data(using: .utf8) else {
            for store in [Store.dataProtection, .legacy] {
                let status = api.delete(query(account, store: store))
                guard status == errSecSuccess || status == errSecItemNotFound || status == errSecMissingEntitlement else {
                    throw KeychainError(status: status)
                }
            }
            return nil
        }
        let status = upsert(data, account: account, store: .dataProtection)
        if status == errSecSuccess {
            _ = api.delete(query(account, store: .legacy))  // drop any stale legacy copy
            return .dataProtection
        }
        guard status == errSecMissingEntitlement else { throw KeychainError(status: status) }
        let legacy = upsert(data, account: account, store: .legacy)
        guard legacy == errSecSuccess else { throw KeychainError(status: legacy) }
        return .legacy
    }

    /// Update in place, adding only when absent, so a failed write never
    /// deletes the existing key first.
    private func upsert(_ data: Data, account: String, store: Store) -> OSStatus {
        let q = query(account, store: store)
        let status = api.update(q, [kSecValueData as String: data])
        guard status == errSecItemNotFound else { return status }
        var add = q
        add[kSecValueData as String] = data
        if store == .dataProtection {
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        return api.add(add)
    }

    func get(account: String) -> String? {
        if let value = read(account, store: .dataProtection) { return value }
        guard let legacy = read(account, store: .legacy) else { return nil }
        // Migrate when the data-protection keychain is usable; otherwise keep
        // using the legacy item.
        if let data = legacy.data(using: .utf8),
           upsert(data, account: account, store: .dataProtection) == errSecSuccess {
            _ = api.delete(query(account, store: .legacy))
        }
        return legacy
    }

    private func read(_ account: String, store: Store) -> String? {
        var q = query(account, store: store)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = api.copyMatching(q)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
