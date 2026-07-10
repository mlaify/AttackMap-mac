import Foundation
import CoreServices

/// Watches a repository directory with FSEvents and fires a debounced callback
/// when non-ignored files change. Ignores our own output (`.attackmap-gui`),
/// VCS, and dependency/build dirs so a re-scan can't feed back into itself.
final class RepoWatcher {
    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "io.mlaify.AttackMap.repowatcher")
    private var debounceItem: DispatchWorkItem?
    private let debounceInterval: TimeInterval
    private let ignored: Set<String>

    /// Called on the watcher's queue after a debounced burst of changes.
    var onChange: (() -> Void)?

    init(debounce: TimeInterval = 1.5,
         ignoring: Set<String> = [
            ".attackmap-gui", ".git", "node_modules", ".build", "dist",
            "build", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
         ]) {
        self.debounceInterval = debounce
        self.ignored = ignoring
    }

    func start(url: URL) {
        stop()
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<RepoWatcher>.fromOpaque(info).takeUnretainedValue()
            let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] ?? []
            watcher.handle(paths: paths)
        }
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil, release: nil, copyDescription: nil)
        let flags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer)
        guard let stream = FSEventStreamCreate(
            kCFAllocatorDefault, callback, &context,
            [url.path] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.5, flags) else { return }
        self.stream = stream
        FSEventStreamSetDispatchQueue(stream, queue)
        FSEventStreamStart(stream)
    }

    func stop() {
        debounceItem?.cancel()
        debounceItem = nil
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    deinit { stop() }

    private func handle(paths: [String]) {
        // Trigger only if at least one changed path is outside the ignored dirs.
        let relevant = paths.contains { path in
            let components = Set(path.split(separator: "/").map(String.init))
            return ignored.isDisjoint(with: components)
        }
        guard relevant else { return }

        debounceItem?.cancel()
        let item = DispatchWorkItem { [weak self] in self?.onChange?() }
        debounceItem = item
        queue.asyncAfter(deadline: .now() + debounceInterval, execute: item)
    }
}
