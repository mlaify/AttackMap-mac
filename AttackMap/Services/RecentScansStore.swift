import Foundation

struct RecentScan: Codable, Identifiable, Hashable {
    var id: String { path }
    let path: String
    let scannedAt: Date

    var url: URL { URL(fileURLWithPath: path) }
    var name: String { url.lastPathComponent }
}

/// Persists the most recently scanned repositories (paths only) in
/// `UserDefaults`, newest first, capped.
enum RecentScansStore {
    private static let key = "recentScans"
    private static let maxCount = 10
    private static let defaults = UserDefaults.standard

    static func all() -> [RecentScan] {
        guard let data = defaults.data(forKey: key),
              let list = try? JSONDecoder().decode([RecentScan].self, from: data) else { return [] }
        return list
    }

    static func record(_ url: URL, at date: Date) {
        var list = all().filter { $0.path != url.path }
        list.insert(RecentScan(path: url.path, scannedAt: date), at: 0)
        if list.count > maxCount { list = Array(list.prefix(maxCount)) }
        if let data = try? JSONEncoder().encode(list) { defaults.set(data, forKey: key) }
    }

    static func clear() { defaults.removeObject(forKey: key) }
}
