#!/usr/bin/env bash
# Extract one version section from a Keep a Changelog document.
# Usage: bash scripts/extract-changelog-section.sh CHANGELOG.md VERSION

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 CHANGELOG.md VERSION" >&2
  exit 2
fi

CHANGELOG_FILE=$1
VERSION=$2

if [[ ! -f "$CHANGELOG_FILE" ]]; then
  echo "ERROR: changelog file does not exist: $CHANGELOG_FILE" >&2
  exit 1
fi

if [[ -z "$VERSION" ]]; then
  echo "ERROR: version must not be empty" >&2
  exit 1
fi

TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT

set +e
awk -v version="$VERSION" '
  BEGIN {
    heading = "## [" version "]"
    found = 0
    duplicate = 0
    in_section = 0
    has_content = 0
  }

  index($0, heading) == 1 &&
    (length($0) == length(heading) || substr($0, length(heading) + 1, 1) == " " || substr($0, length(heading) + 1, 1) == "\t") {
    if (found) {
      duplicate = 1
      in_section = 0
      next
    }
    found = 1
    in_section = 1
    print
    next
  }

  in_section && /^## \[/ {
    in_section = 0
    next
  }

  in_section {
    print
    if ($0 !~ /^[[:space:]]*$/) {
      has_content = 1
    }
  }

  END {
    if (duplicate) exit 2
    if (!found) exit 3
    if (!has_content) exit 4
  }
' "$CHANGELOG_FILE" > "$TMP_FILE"
status=$?
set -e

case "$status" in
  0) cat "$TMP_FILE" ;;
  2) echo "ERROR: changelog contains duplicate entries for version $VERSION" >&2; exit 1 ;;
  3) echo "ERROR: changelog entry not found for version $VERSION" >&2; exit 1 ;;
  4) echo "ERROR: changelog entry is empty for version $VERSION" >&2; exit 1 ;;
  *) echo "ERROR: failed to extract changelog entry for version $VERSION" >&2; exit 1 ;;
esac
