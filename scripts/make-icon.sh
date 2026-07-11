#!/usr/bin/env bash
#
# Rasterize branding/AppIcon-master.svg into the macOS AppIcon.appiconset PNGs.
# Run once after editing the master SVG. Needs an SVG rasterizer:
#   brew install librsvg      # provides rsvg-convert (preferred)
# (cairosvg or inkscape also work if already installed.)
set -euo pipefail

cd "$(dirname "$0")/.."
SRC="branding/AppIcon-master.svg"
OUT="AttackMap/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$OUT"

render() {  # size outfile
  local size="$1" out="$2"
  if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w "$size" -h "$size" "$SRC" -o "$out"
  elif command -v cairosvg >/dev/null 2>&1; then
    cairosvg "$SRC" -W "$size" -H "$size" -o "$out"
  elif command -v inkscape >/dev/null 2>&1; then
    inkscape "$SRC" -w "$size" -h "$size" -o "$out" >/dev/null 2>&1
  else
    echo "error: no SVG rasterizer found. Install one:  brew install librsvg" >&2
    exit 1
  fi
}

# macOS app-icon set: size:filename (some sizes repeat across @1x/@2x slots).
for pair in \
  16:icon_16x16.png    32:icon_16x16@2x.png \
  32:icon_32x32.png    64:icon_32x32@2x.png \
  128:icon_128x128.png 256:icon_128x128@2x.png \
  256:icon_256x256.png 512:icon_256x256@2x.png \
  512:icon_512x512.png 1024:icon_512x512@2x.png; do
  size="${pair%%:*}"; file="${pair##*:}"
  render "$size" "$OUT/$file"
  printf '  %-22s %spx\n' "$file" "$size"
done

echo "Wrote app-icon PNGs to $OUT"
