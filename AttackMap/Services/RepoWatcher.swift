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
    /// The watched root, as given and with symlinks resolved (FSEvents reports
    /// real paths, e.g. /private/var/... for /var/...).
    private var roots: [String] = []

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
        setRoot(url)
        let callback: FSEventStreamCallback = { _, info, _, eventPaths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<RepoWatcher>.fromOpaque(info).takeUnretainedValue()
            // Valid only because the stream is created with UseCFTypes below, so
            // `eventPaths` is a CFArray of CFString (toll-free bridged to
            // NSArray). Without that flag it would be a C `char **` and this
            // cast would crash with EXC_BAD_ACCESS.
            guard let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] else { return }
            watcher.handle(paths: paths)
        }
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil, release: nil, copyDescription: nil)
        let flags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagUseCFTypes
                | kFSEventStreamCreateFlagFileEvents
                | kFSEventStreamCreateFlagNoDefer)
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

    func setRoot(_ url: URL) {
        let given = url.standardizedFileURL.path
        var candidates: Set<String> = [given]
        // FSEvents reports real paths. URL.resolvingSymlinksInPath() *strips*
        // /private, so use realpath(3), plus the /private form of macOS's
        // /tmp, /var and /etc links for paths that don't exist yet.
        if let real = realpath(given, nil) {
            candidates.insert(String(cString: real))
            free(real)
        }
        if ["/tmp/", "/var/", "/etc/"].contains(where: { given.hasPrefix($0) }) {
            candidates.insert("/private" + given)
        }
        roots = candidates.sorted { $0.count > $1.count }
    }

    /// Whether a changed path should trigger a rescan. Ignored directory names
    /// are matched against components *relative to the watched root* (#6):
    /// a repo at ~/build/myrepo must not ignore every event because "build"
    /// appears above it.
    func isRelevant(path: String) -> Bool {
        var relative = path
        for root in roots where path == root || path.hasPrefix(root + "/") {
            relative = String(path.dropFirst(root.count))
            break
        }
        let components = Set(relative.split(separator: "/").map(String.init))
        return ignored.isDisjoint(with: components)
    }

    func handle(paths: [String]) {
        // Trigger only if at least one changed path is outside the ignored dirs.
        guard paths.contains(where: isRelevant(path:)) else { return }

        debounceItem?.cancel()
        let item = DispatchWorkItem { [weak self] in self?.onChange?() }
        debounceItem = item
        queue.asyncAfter(deadline: .now() + debounceInterval, execute: item)
    }
}
