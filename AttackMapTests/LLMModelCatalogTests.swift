import XCTest
@testable import AttackMap

/// `attackmap llm-models --json` decoding (attackmap ≥ 1.1).
final class LLMModelCatalogTests: XCTestCase {
    func testDecodesCodexCatalogWithAccessPrograms() throws {
        let json = """
        {"provider": "openai", "backend": "cli", "note": null, "models": [
          {"id": "gpt-6.2-sol", "display_name": "GPT-6.2-Sol", "provider": "openai", "source": "account",
           "default": true, "gated": null, "efforts": ["low", "medium", "high", "xhigh", "max", "ultra"],
           "fast": true, "access_programs": {"cyber": ["standard"]}, "deprecated": false, "description": "x"},
          {"id": "gpt-6-sol", "display_name": "GPT-6-Sol", "provider": "openai", "source": "account",
           "default": false, "gated": null, "efforts": ["low"], "fast": true,
           "access_programs": {"cyber": ["standard", "daybreak_blue"]}, "deprecated": false, "description": null}
        ]}
        """
        let list = try XCTUnwrap(LLMModelCatalog.decode(Data(json.utf8)))
        XCTAssertEqual(list.models.map(\.id), ["gpt-6.2-sol", "gpt-6-sol"])
        XCTAssertTrue(list.models[0].isDefault)
        XCTAssertEqual(list.models[1].cyberPrograms, ["standard", "daybreak_blue"])
        XCTAssertEqual(list.models[1].label, "GPT-6-Sol (Daybreak)")
    }

    func testDecodesGatedClaudeCatalogEntryAndError() throws {
        let json = """
        {"provider": "claude", "backend": "cli", "note": "catalog", "models": [
          {"id": "claude-mythos-5-2", "display_name": "Claude Mythos 5.2", "provider": "claude",
           "source": "catalog", "default": false, "gated": "verified organizations only",
           "efforts": [], "fast": true, "access_programs": {}, "deprecated": false}
        ]}
        """
        let list = try XCTUnwrap(LLMModelCatalog.decode(Data(json.utf8)))
        XCTAssertEqual(list.note, "catalog")
        XCTAssertEqual(list.models[0].label, "Claude Mythos 5.2 (verified orgs only)")
        let failed = try XCTUnwrap(LLMModelCatalog.decode(Data(#"{"provider": "claude", "error": "no key", "models": []}"#.utf8)))
        XCTAssertEqual(failed.error, "no key")
    }
}
