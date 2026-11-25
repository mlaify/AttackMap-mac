import XCTest
@testable import AttackMap

/// `attackmap llm-models --json` decoding (the command comes from an installed extension).
final class LLMModelCatalogTests: XCTestCase {
    func testDecodesModelListAndIgnoresUnknownFields() throws {
        let json = """
        {"provider": "openai", "backend": "cli", "note": null, "models": [
          {"id": "gpt-6.2-sol", "display_name": "GPT-6.2-Sol", "provider": "openai", "source": "account",
           "default": true, "gated": null, "efforts": ["low", "medium", "high"], "fast": true,
           "some_extension_field": {"x": ["y"]}, "deprecated": false, "description": "x"},
          {"id": "gpt-6-sol", "display_name": "GPT-6-Sol", "provider": "openai", "source": "account",
           "default": false, "gated": null, "efforts": ["low"], "fast": true, "deprecated": true}
        ]}
        """
        let list = try XCTUnwrap(LLMModelCatalog.decode(Data(json.utf8)))
        XCTAssertEqual(list.models.map(\.id), ["gpt-6.2-sol", "gpt-6-sol"])
        XCTAssertTrue(list.models[0].isDefault)
        XCTAssertEqual(list.models[0].label, "GPT-6.2-Sol (default)")
        XCTAssertEqual(list.models[1].label, "GPT-6-Sol (deprecated)")
    }

    func testDecodesRestrictedCatalogEntryAndError() throws {
        let json = """
        {"provider": "claude", "backend": "cli", "note": "catalog", "models": [
          {"id": "claude-x", "display_name": "Claude X", "provider": "claude",
           "source": "catalog", "default": false, "gated": "some organizations only",
           "efforts": [], "fast": false, "deprecated": false}
        ]}
        """
        let list = try XCTUnwrap(LLMModelCatalog.decode(Data(json.utf8)))
        XCTAssertEqual(list.note, "catalog")
        XCTAssertEqual(list.models[0].label, "Claude X (restricted)")
        let failed = try XCTUnwrap(LLMModelCatalog.decode(Data(#"{"provider": "claude", "error": "no key", "models": []}"#.utf8)))
        XCTAssertEqual(failed.error, "no key")
    }

    func testPresetsMatchTheEngineDefaults() {
        XCTAssertEqual(LLMModelCatalog.claudePresets.first(where: \.isDefault)?.id, "claude-opus-5-5")
        XCTAssertEqual(LLMModelCatalog.fastCapableIDs, ["claude-opus-5-5", "claude-fable-5-2", "claude-opus-5"])
    }
}
