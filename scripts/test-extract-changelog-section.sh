#!/usr/bin/env bash
# Tests for extract-changelog-section.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACTOR="$SCRIPT_DIR/extract-changelog-section.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

CHANGELOG="$TMP_DIR/CHANGELOG.md"
cat > "$CHANGELOG" <<'EOF'
# Changelog

## [Unreleased]

## [1.2.3] — 2026-08-06

### Added

- A feature.

### Fixed

- A fix.

## [1.2.2] — 2026-08-01

- An older change.
EOF

EXPECTED=$(cat <<'EOF'
## [1.2.3] — 2026-08-06

### Added

- A feature.

### Fixed

- A fix.
EOF
)
ACTUAL=$(bash "$EXTRACTOR" "$CHANGELOG" 1.2.3)
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "FAIL: extracted section does not match expected content" >&2
  exit 1
fi

if bash "$EXTRACTOR" "$CHANGELOG" 9.9.9 >/dev/null 2>&1; then
  echo "FAIL: missing version should fail" >&2
  exit 1
fi

cat > "$TMP_DIR/duplicate.md" <<'EOF'
## [1.2.3] — 2026-08-06

- First entry.

## [1.2.3] — 2026-08-07

- Duplicate entry.
EOF
if bash "$EXTRACTOR" "$TMP_DIR/duplicate.md" 1.2.3 >/dev/null 2>&1; then
  echo "FAIL: duplicate version should fail" >&2
  exit 1
fi

cat > "$TMP_DIR/empty.md" <<'EOF'
## [1.2.3] — 2026-08-06

## [1.2.2] — 2026-08-01

- An older change.
EOF
if bash "$EXTRACTOR" "$TMP_DIR/empty.md" 1.2.3 >/dev/null 2>&1; then
  echo "FAIL: empty version should fail" >&2
  exit 1
fi

echo "All changelog extractor tests passed."
