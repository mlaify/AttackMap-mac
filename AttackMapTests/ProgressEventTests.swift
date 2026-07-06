import XCTest
@testable import AttackMap

/// Verifies the NDJSON progress protocol (v1) the app consumes from
/// `attackmap analyze --progress-format json`.
final class ProgressEventTests: XCTestCase {
    func testDecodesBeginAdvanceStageDone() throws {
        let begin = try XCTUnwrap(ProgressEvent.decode(
            line: #"{"v":1,"event":"begin","total":1240,"label":"Scanning files"}"#))
        XCTAssertEqual(begin.kind, .begin)
        XCTAssertEqual(begin.total, 1240)

        let advance = try XCTUnwrap(ProgressEvent.decode(
            line: #"{"v":1,"event":"advance","done":620,"total":1240,"current":"src/app.ts"}"#))
        XCTAssertEqual(advance.kind, .advance)
        XCTAssertEqual(advance.fraction, 0.5)
        XCTAssertEqual(advance.current, "src/app.ts")

        let stage = try XCTUnwrap(ProgressEvent.decode(
            line: #"{"v":1,"event":"stage","label":"Taint analysis"}"#))
        XCTAssertEqual(stage.kind, .stage)
        XCTAssertNil(stage.fraction)

        let done = try XCTUnwrap(ProgressEvent.decode(
            line: #"{"v":1,"event":"done","summary":"18 findings","done":1240,"total":1240,"elapsed_s":92.4}"#))
        XCTAssertEqual(done.kind, .done)
        XCTAssertEqual(done.elapsedSeconds, 92.4)
    }

    func testUnknownEventDecodesToUnknown() throws {
        let event = try XCTUnwrap(ProgressEvent.decode(
            line: #"{"v":1,"event":"heartbeat"}"#))
        XCTAssertEqual(event.kind, .unknown)
    }

    func testBlankAndGarbageLinesReturnNil() {
        XCTAssertNil(ProgressEvent.decode(line: ""))
        XCTAssertNil(ProgressEvent.decode(line: "   "))
        XCTAssertNil(ProgressEvent.decode(line: "not json"))
    }
}
