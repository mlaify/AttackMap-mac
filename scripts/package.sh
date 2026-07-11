#!/usr/bin/env bash
#
# Build, sign (Developer ID), notarize, and staple AttackMap.app into a DMG.
#
# Requires: full Xcode (not just Command Line Tools), a "Developer ID
# Application" certificate in your login keychain, and notarization creds.
#
# Usage:
#   TEAM_ID=ABCDE12345 NOTARY_PROFILE=attackmap-notary scripts/package.sh [version]
#
# One-time notarization setup (stores an App Store Connect key or Apple ID in
# the keychain so this script never sees your password):
#   xcrun notarytool store-credentials attackmap-notary \
#     --key /path/AuthKey_XXXX.p8 --key-id XXXX --issuer <issuer-uuid>
#   # …or, with an app-specific password:
#   xcrun notarytool store-credentials attackmap-notary \
#     --apple-id you@example.com --team-id ABCDE12345 --password <app-specific-pw>
#
# Environment:
#   TEAM_ID          (required) Apple Developer team ID.
#   SIGN_ID          Signing identity (default: "Developer ID Application").
#   NOTARY_PROFILE   Keychain profile name for notarytool (default: attackmap-notary).
#   SKIP_NOTARIZE=1  Build + sign + DMG only; skip notarize/staple (dry run).
#
#   For unattended/CI notarization, pass an App Store Connect API key instead of
#   a keychain profile (takes precedence when all three are set):
#   NOTARY_KEY       Path to the AuthKey_XXXX.p8 file.
#   NOTARY_KEY_ID    Key ID.
#   NOTARY_ISSUER    Issuer UUID.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
APP_NAME="AttackMap"
SIGN_ID="${SIGN_ID:-Developer ID Application}"
NOTARY_PROFILE="${NOTARY_PROFILE:-attackmap-notary}"

VERSION="${1:-$(awk -F'"' '/MARKETING_VERSION:/ {print $2; exit}' project.yml)}"
VERSION="${VERSION:-dev}"
DMG="$DIST/${APP_NAME}-${VERSION}.dmg"

log() { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

[[ -n "${TEAM_ID:-}" ]] || die "TEAM_ID is required (your Apple Developer team ID)."

# --- Toolchain: need full Xcode, not just Command Line Tools ---------------
if ! xcodebuild -version >/dev/null 2>&1; then
  if [[ -d /Applications/Xcode.app ]]; then
    export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    log "Using Xcode at $DEVELOPER_DIR"
  fi
fi
xcodebuild -version >/dev/null 2>&1 \
  || die "xcodebuild not found. Install full Xcode and run: sudo xcode-select -s /Applications/Xcode.app"

# --- Regenerate the project so the file list is current --------------------
if command -v xcodegen >/dev/null 2>&1; then
  log "xcodegen generate"
  xcodegen generate >/dev/null
fi

rm -rf "$BUILD" "$DMG"
mkdir -p "$BUILD" "$DIST"

ARCHIVE="$BUILD/${APP_NAME}.xcarchive"
EXPORT_DIR="$BUILD/export"

# --- Archive (Release, Developer ID signed) --------------------------------
# Stamp the version into the bundle when it's a real (numeric) release.
VERSION_ARGS=()
if [[ "$VERSION" =~ ^[0-9] ]]; then
  VERSION_ARGS=(MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$VERSION")
fi

log "Archiving (Release) v${VERSION}…"
xcodebuild archive \
  -project "${APP_NAME}.xcodeproj" \
  -scheme "$APP_NAME" \
  -configuration Release \
  -archivePath "$ARCHIVE" \
  -destination "generic/platform=macOS" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="$SIGN_ID" \
  "${VERSION_ARGS[@]}" \
  | tail -20

# --- Export the .app with a Developer ID profile ---------------------------
EXPORT_PLIST="$BUILD/ExportOptions.plist"
cat > "$EXPORT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>developer-id</string>
  <key>signingStyle</key><string>manual</string>
  <key>teamID</key><string>${TEAM_ID}</string>
</dict>
</plist>
PLIST

log "Exporting .app…"
xcodebuild -exportArchive \
  -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$EXPORT_PLIST" \
  -exportPath "$EXPORT_DIR" \
  | tail -20

APP="$EXPORT_DIR/${APP_NAME}.app"
[[ -d "$APP" ]] || die "Export did not produce $APP"

# --- Build the DMG (drag-to-Applications layout) ---------------------------
log "Building DMG…"
STAGING="$(mktemp -d)"
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGING" \
  -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGING"

log "Signing DMG…"
codesign --force --sign "$SIGN_ID" --timestamp "$DMG"

# --- Notarize + staple ------------------------------------------------------
if [[ "${SKIP_NOTARIZE:-0}" == "1" ]]; then
  log "SKIP_NOTARIZE=1 — built and signed only: $DMG"
  exit 0
fi

log "Submitting to notary service (this can take a few minutes)…"
if [[ -n "${NOTARY_KEY:-}" && -n "${NOTARY_KEY_ID:-}" && -n "${NOTARY_ISSUER:-}" ]]; then
  xcrun notarytool submit "$DMG" \
    --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
else
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
fi

log "Stapling…"
xcrun stapler staple "$DMG"

# --- Verify -----------------------------------------------------------------
log "Verifying signature + Gatekeeper acceptance…"
codesign --verify --deep --strict --verbose=2 "$APP"
spctl -a -t open --context context:primary-signature -vv "$DMG"
xcrun stapler validate "$DMG"

log "Done: $DMG"
