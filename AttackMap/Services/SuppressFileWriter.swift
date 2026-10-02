import Foundation

/// One `.attackmap-suppress.yaml` entry, in the shape core's
/// `suppress.parse_suppress_text` reads (`version: 1`, `suppress:` list):
///
/// ```yaml
/// - rule: "hardcoded-secret"
///   reason: "test fixtures only, never shipped"
///   paths: ["tests/fixtures/**"]
///   expires: 2026-12-31
///   owner: "platform-team"
///   ticket: "SEC-123"
/// ```
struct SuppressRule: Equatable {
    enum Selector: Equatable {
        /// Exactly this finding (its 16-hex id from the report).
        case id(String)
        /// Every finding from this detector (`attackmap rules`), optionally
        /// scoped to `paths`.
        case rule(String)
    }

    var selector: Selector
    var reason: String
    /// Globs scoping a `rule:` entry (`*` within a directory, `**` across).
    /// Ignored for `id:` entries — core would turn them into a separate
    /// path suppression.
    var paths: [String] = []
    /// After this day the entry stops applying (core #238).
    var expires: Date?
    var owner: String?
    var ticket: String?
}

enum SuppressFileError: Error, LocalizedError, Equatable {
    case emptyReason
    case invalidFindingId(String)
    case emptyRule
    case matchEverythingGlob(String)
    case unsupportedLayout(String)

    var errorDescription: String? {
        switch self {
        case .emptyReason:
            return "A reason is required — core skips suppressions without one."
        case .invalidFindingId(let id):
            return "\"\(id)\" isn't a 16-hex finding id."
        case .emptyRule:
            return "The rule id is empty."
        case .matchEverythingGlob(let glob):
            return "Path \"\(glob)\" would suppress every file in the repo; scope it (e.g. tests/fixtures/**)."
        case .unsupportedLayout(let why):
            return "Couldn't safely add to the existing suppress file (\(why)). Add the entry by hand."
        }
    }
}

/// Appends suppression entries to a repo's suppress file without disturbing
/// what's already there (comments, ordering, formatting). Only ever called on
/// an explicit user action from the Suppress sheet.
///
/// Every string value is written double-quoted with YAML escapes, so a reason
/// containing `:`, `#`, quotes or newlines — or an id that looks numeric —
/// can't change the document's structure or type.
enum SuppressFileWriter {
    /// Core's discovery order at the repo root.
    static let filenames = [".attackmap-suppress.yaml", ".attackmap-suppress.yml"]

    /// The file a new entry goes to: an explicit `--suppress-file` override,
    /// else the repo's existing suppress file, else a new
    /// `.attackmap-suppress.yaml` at the root.
    static func targetURL(repoURL: URL, override: URL? = nil,
                          fileManager: FileManager = .default) -> URL {
        if let override { return override }
        for name in filenames {
            let candidate = repoURL.appendingPathComponent(name)
            if fileManager.fileExists(atPath: candidate.path) { return candidate }
        }
        return repoURL.appendingPathComponent(filenames[0])
    }

    /// Reject what core would skip (with a warning) so the user finds out now,
    /// not after a rescan that silently didn't suppress anything.
    static func validate(_ rule: SuppressRule) throws {
        if rule.reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw SuppressFileError.emptyReason
        }
        switch rule.selector {
        case .id(let id):
            let trimmed = id.trimmingCharacters(in: .whitespaces)
            let hex = trimmed.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
            if trimmed.count != 16 || !hex { throw SuppressFileError.invalidFindingId(id) }
        case .rule(let ruleId):
            if ruleId.trimmingCharacters(in: .whitespaces).isEmpty { throw SuppressFileError.emptyRule }
            for glob in cleaned(rule.paths) where isMatchEverythingGlob(glob) {
                throw SuppressFileError.matchEverythingGlob(glob)
            }
        }
    }

    /// Trimmed, non-empty globs.
    static func cleaned(_ paths: [String]) -> [String] {
        paths.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// Core's `is_match_everything_glob`: `*`, `**`, `**/*`, `/`, `.` …
    static func isMatchEverythingGlob(_ glob: String) -> Bool {
        let stripped = glob.trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return stripped.replacingOccurrences(of: "*", with: "")
            .replacingOccurrences(of: "/", with: "")
            .replacingOccurrences(of: ".", with: "")
            .isEmpty
    }

    // MARK: Rendering

    /// `YYYY-MM-DD` in the user's calendar day (what they picked in the sheet).
    static func dayString(_ date: Date, calendar: Calendar = .current) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }

    /// A YAML double-quoted scalar.
    static func quoted(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{85}": out += "\\N"
            case "\u{2028}": out += "\\L"
            case "\u{2029}": out += "\\P"
            default:
                if scalar.value < 0x20 || scalar.value == 0x7F {
                    out += String(format: "\\x%02X", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    /// The entry as YAML lines (no trailing newline), its `- ` at `indent`.
    static func entryLines(_ rule: SuppressRule, indent: Int, calendar: Calendar = .current) -> [String] {
        let pad = String(repeating: " ", count: indent)
        let inner = pad + "  "
        var fields: [String] = []
        switch rule.selector {
        case .id(let id):
            fields.append("id: " + quoted(id.trimmingCharacters(in: .whitespaces)))
        case .rule(let ruleId):
            fields.append("rule: " + quoted(ruleId.trimmingCharacters(in: .whitespaces)))
        }
        fields.append("reason: " + quoted(rule.reason.trimmingCharacters(in: .whitespacesAndNewlines)))
        if case .rule = rule.selector {
            let globs = cleaned(rule.paths)
            if !globs.isEmpty { fields.append("paths: [" + globs.map(quoted).joined(separator: ", ") + "]") }
        }
        if let expires = rule.expires { fields.append("expires: " + dayString(expires, calendar: calendar)) }
        if let owner = rule.owner?.trimmingCharacters(in: .whitespacesAndNewlines), !owner.isEmpty {
            fields.append("owner: " + quoted(owner))
        }
        if let ticket = rule.ticket?.trimmingCharacters(in: .whitespacesAndNewlines), !ticket.isEmpty {
            fields.append("ticket: " + quoted(ticket))
        }
        return fields.enumerated().map { index, field in (index == 0 ? pad + "- " : inner) + field }
    }

    // MARK: Appending

    /// `existing` (the current file content, or nil when there's no file)
    /// with `rule` added to its suppression list. Existing text is preserved
    /// byte-for-byte; the entry is spliced in at the end of the `suppress:`
    /// block (or the top-level list), matching the file's list indentation
    /// and line endings.
    static func appending(_ rule: SuppressRule, to existing: String?,
                          calendar: Calendar = .current) throws -> String {
        try validate(rule)
        let text = existing ?? ""
        let newline = text.contains("\r\n") ? "\r\n" : "\n"
        let lines = splitLines(text)
        let topLevel = lines.indices.filter { isTopLevelContent(lines[$0]) }

        // Empty / comments-only file: write the canonical header.
        if topLevel.isEmpty {
            let block = ["version: 1", "suppress:"] + entryLines(rule, indent: 2, calendar: calendar)
            return joinAppending(text, block, newline: newline)
        }

        // Top-level list (core accepts a bare list of entries).
        if topLevel.allSatisfy({ isSequenceItem(lines[$0]) }) {
            return joinAppending(text, entryLines(rule, indent: 0, calendar: calendar), newline: newline)
        }

        // Mapping: find `suppress:` (core prefers it), else `suppressions:`.
        let keyIndex = topLevel.first { keyName(lines[$0]) == "suppress" }
            ?? topLevel.first { keyName(lines[$0]) == "suppressions" }
        guard let keyIndex else {
            // A mapping without a list yet (e.g. just `version: 1`).
            let block = ["suppress:"] + entryLines(rule, indent: 2, calendar: calendar)
            return joinAppending(text, block, newline: newline)
        }

        var lines2 = lines
        let value = keyValue(lines[keyIndex])
        if value == "[]" {
            // `suppress: []` → block style, then append.
            let key = keyName(lines[keyIndex]) ?? "suppress"
            lines2[keyIndex] = key + ":"
        } else if !value.isEmpty {
            throw SuppressFileError.unsupportedLayout("its suppress list is written in flow style")
        }

        // The block runs until the next top-level key (an indentless `- ` item
        // at column 0 still belongs to it).
        let nextKey = topLevel.first { $0 > keyIndex && !isSequenceItem(lines[$0]) }
        let blockEnd = nextKey ?? lines2.count
        let indent = (keyIndex + 1..<blockEnd).lazy
            .compactMap { sequenceIndent(lines2[$0]) }
            .first ?? 2
        let entry = entryLines(rule, indent: indent, calendar: calendar)

        if nextKey == nil {
            return joinAppending(lines2.joined(separator: newline), entry, newline: newline)
        }
        // Insert after the block's last content line, before any blank lines /
        // comments that lead into the next key.
        var insertAt = blockEnd
        while insertAt - 1 > keyIndex,
              lines2[insertAt - 1].trimmingCharacters(in: .whitespaces).isEmpty
                || lines2[insertAt - 1].trimmingCharacters(in: .whitespaces).hasPrefix("#") {
            insertAt -= 1
        }
        lines2.insert(contentsOf: entry, at: insertAt)
        return lines2.joined(separator: newline) + (endsWithNewline(text) ? newline : "")
    }

    /// Validate, splice and write. Creates the file (and its directory) when
    /// missing. Returns the written text.
    @discardableResult
    static func append(_ rule: SuppressRule, to url: URL,
                       fileManager: FileManager = .default) throws -> String {
        let existing: String?
        if fileManager.fileExists(atPath: url.path) {
            existing = try String(contentsOf: url, encoding: .utf8)
        } else {
            existing = nil
        }
        let updated = try appending(rule, to: existing)
        try fileManager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(updated.utf8).write(to: url, options: .atomic)
        return updated
    }

    // MARK: Line helpers

    /// Lines without terminators (handles `\n` and `\r\n`); a trailing
    /// newline doesn't produce an empty last element.
    private static func splitLines(_ text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        var lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if endsWithNewline(text) { lines.removeLast() }
        return lines
    }

    /// Text + `block` on new lines, always ending in a newline.
    private static func joinAppending(_ text: String, _ block: [String], newline: String) -> String {
        var out = text
        if !out.isEmpty && !endsWithNewline(out) { out += newline }
        return out + block.joined(separator: newline) + newline
    }

    /// Scalar-level check: Swift treats `\r\n` as one Character, so
    /// `hasSuffix("\n")` is false for CRLF text.
    private static func endsWithNewline(_ text: String) -> Bool {
        text.unicodeScalars.last == "\n"
    }

    /// A column-0 line that is YAML content (not blank, comment, or a
    /// document marker).
    private static func isTopLevelContent(_ line: String) -> Bool {
        guard let first = line.first, first != " ", first != "\t", first != "#" else { return false }
        return !(line.hasPrefix("---") || line.hasPrefix("..."))
    }

    private static func isSequenceItem(_ line: String) -> Bool {
        line == "-" || line.hasPrefix("- ")
    }

    /// The indentation of a `- ` sequence item line, if it is one.
    private static func sequenceIndent(_ line: String) -> Int? {
        let spaces = line.prefix { $0 == " " }.count
        let rest = line.dropFirst(spaces)
        return (rest == "-" || rest.hasPrefix("- ")) ? spaces : nil
    }

    /// `key` of a top-level `key: value` line.
    private static func keyName(_ line: String) -> String? {
        guard let colon = line.firstIndex(of: ":") else { return nil }
        let key = line[..<colon].trimmingCharacters(in: .whitespaces)
        let unquoted = key.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        return unquoted.isEmpty ? nil : unquoted
    }

    /// The value after `key:` with any trailing comment removed.
    private static func keyValue(_ line: String) -> String {
        guard let colon = line.firstIndex(of: ":") else { return "" }
        var value = String(line[line.index(after: colon)...])
        if let hash = value.range(of: " #") ?? (value.hasPrefix("#") ? value.range(of: "#") : nil) {
            value = String(value[..<hash.lowerBound])
        }
        return value.trimmingCharacters(in: .whitespaces)
    }
}
