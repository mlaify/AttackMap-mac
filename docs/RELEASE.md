# Building a signed, notarized AttackMap.app

The app ships as a **Developer ID–signed, notarized, stapled DMG** so users can
open it without Gatekeeper warnings. Two paths, same `scripts/package.sh`:

- **CI (recommended):** push a `vX.Y.Z` tag → `.github/workflows/release.yml`
  builds on a macOS runner and attaches the DMG to the GitHub Release.
- **Local:** run `scripts/package.sh` on a Mac with full Xcode + your cert.

Notarization is **impossible** without a paid Apple Developer Program membership
and a *Developer ID Application* certificate. There is no way around that — it's
an Apple requirement, not ours.

---

## One-time setup

### 1. Developer ID Application certificate
In Xcode → Settings → Accounts → Manage Certificates → **+** → *Developer ID
Application* (or create it in the Apple Developer portal). Confirm it's present:

```sh
security find-identity -v -p codesigning   # should list "Developer ID Application: … (TEAMID)"
```

Your **Team ID** is the 10-char code in parentheses (also in the Developer
portal → Membership).

### 2. App Store Connect API key (for notarytool)
Developer portal → **Users and Access → Integrations → App Store Connect API** →
generate a key with the **Developer** role. Download the `AuthKey_XXXX.p8`
(one download only). Note the **Key ID** and the **Issuer ID**.

> An Apple ID + app-specific password also works, but an API key is cleaner for
> CI and never exposes a password.

---

## Local build

Store the notarization credentials in your keychain once (so the script never
sees them):

```sh
xcrun notarytool store-credentials attackmap-notary \
  --key ~/keys/AuthKey_XXXX.p8 --key-id XXXX --issuer <issuer-uuid>
```

Then build:

```sh
TEAM_ID=ABCDE12345 NOTARY_PROFILE=attackmap-notary scripts/package.sh 0.1.0
# → dist/AttackMap-0.1.0.dmg  (signed, notarized, stapled)
```

Dry run (build + sign + DMG, no notarization):

```sh
TEAM_ID=ABCDE12345 SKIP_NOTARIZE=1 scripts/package.sh 0.1.0
```

If `xcodebuild` isn't found, point it at full Xcode:
`sudo xcode-select -s /Applications/Xcode.app`.

---

## CI release

Add these **repository secrets** (Settings → Secrets and variables → Actions):

| Secret | What it is | How to produce |
|---|---|---|
| `MACOS_DEV_ID_CERT_P12` | Base64 of the Developer ID cert **+ private key**, exported as `.p12` | Keychain Access → right-click the identity → Export → `.p12`; then `base64 -i cert.p12 \| pbcopy` |
| `MACOS_CERT_PASSWORD` | The password you set when exporting the `.p12` | — |
| `APPLE_TEAM_ID` | Your 10-char Team ID | Developer portal → Membership |
| `NOTARY_KEY_P8` | Base64 of `AuthKey_XXXX.p8` | `base64 -i AuthKey_XXXX.p8 \| pbcopy` |
| `NOTARY_KEY_ID` | App Store Connect API **Key ID** | shown when you created the key |
| `NOTARY_ISSUER_ID` | App Store Connect API **Issuer ID** | Integrations page |
| `TAP_TOKEN` | Token that can push + open PRs on `mlaify/homebrew-tap` | Fine-grained PAT scoped to that repo with **Contents: write** + **Pull requests: write** |

`GITHUB_TOKEN` is provided automatically. No keychain password secret is needed
— the workflow generates an ephemeral one and deletes the temp keychain after.
`TAP_TOKEN` is only used to bump the Homebrew cask (below); omit it and that
step is skipped.

Then cut a release:

```sh
git tag -a v0.1.0 -m "AttackMap.app 0.1.0"
git push origin v0.1.0
```

The workflow imports the cert into a throwaway keychain, archives + exports with
the Developer ID profile, builds/sign/notarizes/staples the DMG, uploads it to
the Release, and wipes the credentials.

---

## Updates via Homebrew cask

The app updates through Homebrew — the same place the CLI it drives lives. On
each tagged release the workflow renders [`packaging/attackmap-app.rb`](../packaging/attackmap-app.rb)
with the new version + the notarized DMG's sha256 and opens a PR against
`mlaify/homebrew-tap` (`Casks/attackmap-app.rb`). Merge that PR and users get:

```sh
brew install --cask mlaify/tap/attackmap-app   # pulls the CLI formula too (dependency)
brew upgrade --cask attackmap-app              # updates the app
```

Because the cask `depends_on formula: "mlaify/tap/attackmap"`, `brew upgrade`
keeps the app and the CLI it drives in lockstep.

> **First release:** there's no cask in the tap until the first `vX.Y.Z` app tag
> ships — that release opens the initial cask PR. Merge it, then the install
> command above works.

## Verifying a build

```sh
spctl -a -t open --context context:primary-signature -vv dist/AttackMap-*.dmg  # → accepted
xcrun stapler validate dist/AttackMap-*.dmg                                     # → validated
codesign --verify --deep --strict --verbose=2 /Volumes/AttackMap/AttackMap.app # after mounting
```

`scripts/package.sh` runs all three at the end, so a green run is already
verified.

---

## Notes

- The app is **not sandboxed** (it spawns the `attackmap` CLI and reads
  arbitrary repo folders) but **is** hardened-runtime + signed + notarized —
  which is all Gatekeeper requires for distribution outside the App Store. No
  special entitlements are needed; spawning a subprocess and reading
  user-selected files are allowed under a non-sandboxed hardened runtime.
- Users still need the `attackmap` CLI installed (`brew install
  mlaify/tap/attackmap`) — the app drives it, it doesn't bundle it.
