#!/usr/bin/env bash
# =============================================================================
# Package CRISPR AuthBahn WebExtension into a clean, distributable ZIP release.
# Strips out macOS metadata (__MACOSX, ._*), .git, and temporary files.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
EXT_SRC="$REPO_ROOT/AuthBahn"
VERSION=$(grep '"version"' "$EXT_SRC/manifest.json" | head -1 | sed -E 's/.*"version": "([^"]+)".*/\1/')
OUTPUT_ZIP="$DIST_DIR/AuthBahn-v${VERSION}.zip"

mkdir -p "$DIST_DIR"
rm -f "$OUTPUT_ZIP"

echo "Packaging AuthBahn v${VERSION}..."
(
  cd "$EXT_SRC"
  # Exclude any hidden files, .DS_Store, __MACOSX, or backups
  zip -r "$OUTPUT_ZIP" . \
    -x "*.DS_Store" \
    -x "__MACOSX*" \
    -x "*/.*" \
    -x ".*" \
    -x "*~" \
    -x "*.bak"
)

echo "[OK] Created release archive: $OUTPUT_ZIP"
unzip -l "$OUTPUT_ZIP"
