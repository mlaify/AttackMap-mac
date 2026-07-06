import Foundation

/// One event from `attackmap analyze --progress-format json`, emitted as
/// newline-delimited JSON on the child process's stderr.
///
/// Protocol version 1 (`"v": 1`). A scan runs several analyzer sub-passes, so
/// the stream contains **multiple** `begin → advance… → stage… → done` cycles —
/// treat each `begin` as a determinate-bar reset and the child process exit as
/// the authoritative completion signal. Unknown event kinds decode to
/// `.unknown` and should be ignored.
struct ProgressEvent: Decodable, Equatable {
    enum Kind: String, Decodable {
        case begin, advance, stage, done, unknown
    }

    let version: Int
    let kind: Kind
    let total: Int?
    let done: Int?
    let current: String?
    let label: String?
    let summary: String?
    let elapsedSeconds: Double?

    enum CodingKeys: String, CodingKey {
        case version = "v"
        case event
        case total, done, current, label, summary
        case elapsedSeconds = "elapsed_s"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = (try? c.decode(Int.self, forKey: .version)) ?? 1
        let raw = (try? c.decode(String.self, forKey: .event)) ?? "unknown"
        kind = Kind(rawValue: raw) ?? .unknown
        total = try? c.decode(Int.self, forKey: .total)
        done = try? c.decode(Int.self, forKey: .done)
        current = try? c.decode(String.self, forKey: .current)
        label = try? c.decode(String.self, forKey: .label)
        summary = try? c.decode(String.self, forKey: .summary)
        elapsedSeconds = try? c.decode(Double.self, forKey: .elapsedSeconds)
    }

    /// Fraction complete for the current determinate sub-pass, if known.
    var fraction: Double? {
        guard let done, let total, total > 0 else { return nil }
        return min(1.0, Double(done) / Double(total))
    }

    /// Decode a single NDJSON line, or `nil` if the line isn't a valid event.
    static func decode(line: String, using decoder: JSONDecoder = JSONDecoder()) -> ProgressEvent? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else { return nil }
        return try? decoder.decode(ProgressEvent.self, from: data)
    }
}
