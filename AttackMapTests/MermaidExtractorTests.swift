import XCTest
@testable import AttackMap

final class MermaidExtractorTests: XCTestCase {
    func testExtractsTitledBlocksAndStripsOrdinal() {
        let md = """
        # AttackMap — Attack paths

        ## 1. Public input into sensitive data path

        ```mermaid
        flowchart TD
          A --> B
        ```

        ## 2. Second path

        ```mermaid
        graph LR
          C --> D
        ```
        """
        let diagrams = MermaidExtractor.diagrams(fromMarkdown: md)
        XCTAssertEqual(diagrams.count, 2)
        XCTAssertEqual(diagrams[0].title, "Public input into sensitive data path")
        XCTAssertEqual(diagrams[1].title, "Second path")
        XCTAssertTrue(diagrams[0].code.contains("flowchart TD"))
    }

    func testNoMermaidBlocksYieldsEmpty() {
        XCTAssertTrue(MermaidExtractor.diagrams(fromMarkdown: "# Just prose\n\nNo diagrams here.").isEmpty)
    }

    func testIgnoresNonMermaidFences() {
        let md = "## Code\n\n```swift\nlet x = 1\n```\n"
        XCTAssertTrue(MermaidExtractor.diagrams(fromMarkdown: md).isEmpty)
    }
}
