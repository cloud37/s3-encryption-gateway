#!/usr/bin/env bash
# Backfill GitHub Release notes from CHANGELOG.md.
# This is intentionally local-only and is not referenced by CI.
# Use --apply to perform GitHub mutations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(dirname "$SCRIPT_DIR")"
EXTRACTOR="$SCRIPT_DIR/extract-changelog-section.sh"
CHANGELOG_FILE="$REPOSITORY_ROOT/CHANGELOG.md"
RELEASE_PREFIX="s3-encryption-gateway-"
REPOSITORY=""
LIMIT=1000
VERSION=""
APPLY=false

usage() {
  cat >&2 <<'EOF'
Usage: backfill-release-notes.sh [OPTIONS]

List existing project releases and preview changelog-based note updates.
Nothing is changed unless --apply is supplied.

Options:
  --apply             Update GitHub Releases with gh release edit.
  --limit NUMBER      Maximum releases to inspect (default: 1000).
  --version VERSION   Update only the specified release version.
  --repo OWNER/REPO   Repository passed to gh (default: current repository).
  -h, --help          Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=true; shift ;;
    --limit)
      if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERROR: --limit requires a positive integer" >&2
        exit 2
      fi
      LIMIT=$2
      shift 2
      ;;
    --version)
      if [[ $# -lt 2 || -z "$2" || "$2" == *[!0-9A-Za-z.-]* ]]; then
        echo "ERROR: --version requires a valid release version" >&2
        exit 2
      fi
      VERSION=$2
      shift 2
      ;;
    --repo)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "ERROR: --repo requires OWNER/REPO" >&2
        exit 2
      fi
      REPOSITORY=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -x "$EXTRACTOR" ]]; then
  echo "ERROR: changelog extractor is not executable: $EXTRACTOR" >&2
  echo "Run: chmod +x scripts/extract-changelog-section.sh" >&2
  exit 1
fi

if [[ ! -f "$CHANGELOG_FILE" ]]; then
  echo "ERROR: changelog file does not exist: $CHANGELOG_FILE" >&2
  exit 1
fi

REPO_ARGS=()
if [[ -n "$REPOSITORY" ]]; then
  REPO_ARGS+=(--repo "$REPOSITORY")
fi

echo "Fetching up to $LIMIT releases..."
if [[ -n "$VERSION" ]]; then
  RELEASE_TAGS=("$RELEASE_PREFIX$VERSION")
else
  mapfile -t RELEASE_TAGS < <(
    gh release list "${REPO_ARGS[@]}" --limit "$LIMIT" --json tagName,isDraft \
      --jq '.[] | select(.isDraft == false) | .tagName'
  )
fi

if [[ ${#RELEASE_TAGS[@]} -eq 0 ]]; then
  echo "No published releases found."
  exit 0
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

updated=0
skipped=0
failed=0

for release_tag in "${RELEASE_TAGS[@]}"; do
  if [[ "$release_tag" != "$RELEASE_PREFIX"* ]]; then
    echo "SKIP  $release_tag (unrelated release tag)"
    skipped=$((skipped + 1))
    continue
  fi

  version=${release_tag#"$RELEASE_PREFIX"}
  if [[ -z "$version" || "$version" == *[!0-9A-Za-z.-]* ]]; then
    echo "SKIP  $release_tag (could not derive a valid version)"
    skipped=$((skipped + 1))
    continue
  fi

  notes_file="$TMP_DIR/$version.md"
  if ! "$EXTRACTOR" "$CHANGELOG_FILE" "$version" > "$notes_file"; then
    echo "ERROR $release_tag (no usable changelog section)" >&2
    failed=$((failed + 1))
    continue
  fi

  release_notes_file="$TMP_DIR/$version-release.md"
  {
    cat "$notes_file"
    printf '\nSee the [full changelog](https://github.com/%s/blob/main/CHANGELOG.md).\n' \
      "${REPOSITORY:-cloud37/s3-encryption-gateway}"
  } > "$release_notes_file"

  if [[ "$APPLY" == true ]]; then
    gh release edit "$release_tag" \
      --notes-file "$release_notes_file" \
      "${REPO_ARGS[@]}"
    echo "UPDATED $release_tag"
  else
    echo "WOULD UPDATE $release_tag"
  fi
  updated=$((updated + 1))
done

echo
if [[ "$APPLY" == true ]]; then
  echo "Updated: $updated; skipped: $skipped; failed: $failed"
else
  echo "Would update: $updated; skipped: $skipped; failed: $failed"
  echo "No GitHub releases were changed. Re-run with --apply to apply updates."
fi

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
