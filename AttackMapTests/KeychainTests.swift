import Security
import XCTest
@testable import AttackMap

/// Keychain wrapper against a mocked SecItem layer (#8).
final class KeychainTests: XCTestCase {
    /// In-memory SecItem stand-in: two stores keyed by account, with
    /// configurable failures.
    final class MockSecItem: SecItemAPI, @unchecked Sendable {
        var dataProtection: [String: Data] = [:]
        var legacy: [String: Data] = [:]
        var dataProtectionStatus: OSStatus = errSecSuccess   // e.g. errSecMissingEntitlement
        var failWrites: OSStatus?                           // e.g. errSecInteractionNotAllowed

        private func isDP(_ q: [String: Any]) -> Bool { (q[kSecUseDataProtectionKeychain as String] as? Bool) == true }
        private func account(_ q: [String: Any]) -> String { q[kSecAttrAccount as String] as! String }

        func add(_ a: [String: Any]) -> OSStatus {
            if isDP(a), dataProtectionStatus != errSecSuccess { return dataProtectionStatus }
            if let failWrites { return failWrites }
            let data = a[kSecValueData as String] as! Data
            if isDP(a) { dataProtection[account(a)] = data } else { legacy[account(a)] = data }
            return errSecSuccess
        }

        func update(_ q: [String: Any], _ a: [String: Any]) -> OSStatus {
            if isDP(q), dataProtectionStatus != errSecSuccess { return dataProtectionStatus }
            if let failWrites { return failWrites }
            let data = a[kSecValueData as String] as! Data
            if isDP(q) {
                guard dataProtection[account(q)] != nil else { return errSecItemNotFound }
                dataProtection[account(q)] = data
            } else {
                guard legacy[account(q)] != nil else { return errSecItemNotFound }
                legacy[account(q)] = data
            }
            return errSecSuccess
        }

        func copyMatching(_ q: [String: Any]) -> (OSStatus, AnyObject?) {
            if isDP(q), dataProtectionStatus != errSecSuccess { return (dataProtectionStatus, nil) }
            let value = isDP(q) ? dataProtection[account(q)] : legacy[account(q)]
            return value.map { (errSecSuccess, $0 as AnyObject) } ?? (errSecItemNotFound, nil)
        }

        func delete(_ q: [String: Any]) -> OSStatus {
            if isDP(q), dataProtectionStatus != errSecSuccess { return dataProtectionStatus }
            let removed = isDP(q) ? dataProtection.removeValue(forKey: account(q)) : legacy.removeValue(forKey: account(q))
            return removed == nil ? errSecItemNotFound : errSecSuccess
        }
    }

    func testSavesToDataProtectionKeychain() throws {
        let mock = MockSecItem()
        let keychain = Keychain(api: mock)
        XCTAssertEqual(try keychain.set("k1", account: "A"), .dataProtection)
        XCTAssertEqual(try keychain.set("k2", account: "A"), .dataProtection)  // update in place
        XCTAssertEqual(keychain.get(account: "A"), "k2")
        XCTAssertTrue(mock.legacy.isEmpty)
    }

    func testFailedSaveThrowsAndKeepsTheOldKey() throws {
        let mock = MockSecItem()
        let keychain = Keychain(api: mock)
        try keychain.set("old", account: "A")
        mock.failWrites = errSecInteractionNotAllowed
        XCTAssertThrowsError(try keychain.set("new", account: "A")) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError(status: errSecInteractionNotAllowed))
        }
        mock.failWrites = nil
        XCTAssertEqual(keychain.get(account: "A"), "old", "a failed save must not delete the existing key")
    }

    func testFallsBackToLegacyWhenNotEntitled() throws {
        let mock = MockSecItem()
        mock.dataProtectionStatus = errSecMissingEntitlement
        let keychain = Keychain(api: mock)
        XCTAssertEqual(try keychain.set("k", account: "A"), .legacy)
        XCTAssertEqual(keychain.get(account: "A"), "k")
        XCTAssertNil(try keychain.set(nil, account: "A"))
        XCTAssertNil(keychain.get(account: "A"))
    }

    func testLegacyItemMigratesOnRead() {
        let mock = MockSecItem()
        mock.legacy["A"] = Data("legacy-key".utf8)
        let keychain = Keychain(api: mock)
        XCTAssertEqual(keychain.get(account: "A"), "legacy-key")
        XCTAssertEqual(mock.dataProtection["A"], Data("legacy-key".utf8))
        XCTAssertNil(mock.legacy["A"])
    }

    func testSettingsShowsTheFailure() {
        XCTAssertTrue(KeychainError(status: errSecInteractionNotAllowed).errorDescription!.hasPrefix("Couldn't save to the Keychain"))
    }
}
