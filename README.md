# AttackMap for macOS

A native macOS GUI for [AttackMap](https://github.com/mlaify/AttackMap), the
local-first defensive security analyzer. Point it at a repository, run a scan,
watch live progress, and browse the findings — all driving the `attackmap` CLI
you already have installed.

> **Status:** early scaffold (v0.1.0-dev). Milestone **M1** (spawn the CLI +
> decode its report) is implemented and its core is verified; the SwiftUI views
> are a working skeleton. See the
> [implementation plan](https://github.com/mlaify/AttackMap/blob/main/docs/macos-gui-plan.md).

## What it is

This is a **dev tool**: a thin launcher + viewer over the AttackMap engine. It
does not reimplement any analysis — it spawns `attackmap analyze … --format json
--progress-format json`, streams the NDJSON progress, and renders the
`attackmap-report.json` artifacts. Because it shells out to the installed CLI,
there's no bundled Python and no notarization required for local use.

## Requirements

- **macOS 15 (Sequoia)** or later
- **Xcode 16+** to build
- **[XcodeGen](https://github.com/yonabb/XcodeGen)** to generate the project
  (`brew install xcodegen`)
- The **`attackmap` CLI** on your `PATH` (`brew install mlaify/tap/attackmap`)

## Build & run

```bash
brew install xcodegen          # one-time
xcodegen generate              # creates AttackMap.xcodeproj from project.yml
open AttackMap.xcodeproj        # build & run in Xcode (⌘R)
```

The `.xcodeproj` is generated from [`project.yml`](project.yml) and is
git-ignored — `project.yml` is the source of truth. The app is **not**
sandboxed (it must spawn the CLI and read arbitrary repo folders).

## Architecture

```
SwiftUI app ──► ProcessRunner ──► attackmap analyze … --progress-format json
                     │  stderr (NDJSON)  ──► ScanViewModel (live progress)
                     │  exit 0 + reports/attackmap-report.json
                     ▼
               Report.load(…)  ──► Codable models ──► Table / detail views
```

| Layer | Files | Notes |
|---|---|---|
| Models (Foundation-only, testable) | `Models/Report.swift`, `Models/ProgressEvent.swift`, `Models/ScanConfig.swift` | Tolerant `Codable` over the engine's JSON |
| Services (Foundation-only) | `Services/CLILocator.swift`, `Services/ProcessRunner.swift` | Find the CLI, spawn + stream + cancel |
| View model | `ViewModels/ScanViewModel.swift` | `@Observable`, folds progress into state |
| Views | `AttackMapApp.swift`, `Views/ContentView.swift` | SwiftUI skeleton |

The Models + Services layer is deliberately UI-free so it stays unit-testable;
`AttackMapTests` decodes a real report fixture and the NDJSON protocol.

## Roadmap

M1 spawn+parse ✅ · M2 core UI · M3 rich views (exploitability / paths / surface
/ review) · M4 diagrams + settings + recents · M5 watch mode. Full plan lives in
the engine repo: [`docs/macos-gui-plan.md`](https://github.com/mlaify/AttackMap/blob/main/docs/macos-gui-plan.md).

## License

MIT — see [LICENSE](LICENSE).
