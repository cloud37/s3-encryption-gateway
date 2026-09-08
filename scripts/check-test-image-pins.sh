#!/usr/bin/env bash
set -euo pipefail

# Keep this check deliberately independent of Renovate.  It validates the
# source-of-truth inventory and the exact shape consumed by renovate.json,
# rather than merely looking for the word "renovate".
python3 - <<'PY'
from pathlib import Path
import re
import sys

files = sorted(Path("test").rglob("*.go"))
baseline = "RELEASE.2024-11-07T00-52-20Z"
channel = re.compile(r"^(latest|edge|nightly|stable|main|master|dev|canary)$", re.I)
annotation = re.compile(
    r"^// renovate: datasource=(?P<datasource>\S+) depName=(?P<dep>\S+) "
    r"versioning=(?P<versioning>\S+)$"
)
image_decl = re.compile(r'^\s*const\s+(?P<name>\w+Image)\s*=\s*"(?P<value>[^"]+)"\s*$')
version_decl = re.compile(r'^\s*const\s+(?P<name>\w+Version)\s*=\s*"(?P<value>[^"]+)"\s*$')
image_field = re.compile(r'\bImage\s*:\s*"')

found = []
for path in files:
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        match = image_decl.match(line) or version_decl.match(line)
        if not match:
            continue
        value = match.group("value")
        name = match.group("name")
        # Azurite is a deliberately unmanaged legacy integration fixture.
        if name == "azuriteImage":
            if value.rsplit(":", 1)[-1] in {"latest", "edge", "nightly", "stable"}:
                raise SystemExit(f"{path}:{i+1}: legacy Azurite still uses a mutable tag")
            continue
        if i == 0 or not annotation.match(lines[i - 1]):
            raise SystemExit(f"{path}:{i+1}: {name} must have an adjacent Renovate annotation")
        ann = annotation.match(lines[i - 1]).groupdict()
        if name.endswith("Image"):
            if ann["datasource"] != "docker" or ann["versioning"] != "docker":
                raise SystemExit(f"{path}:{i+1}: image {name} has inconsistent datasource/versioning")
            if ":" not in value:
                raise SystemExit(f"{path}:{i+1}: image {name} has no explicit tag")
            dep, tag = value.rsplit(":", 1)
            if dep != ann["dep"] or ann["dep"] == "" or channel.fullmatch(tag):
                raise SystemExit(f"{path}:{i+1}: annotation/value mismatch for {name}")
            if ann["dep"] in {"minio/minio", "quay.io/minio/minio"} and tag != baseline:
                raise SystemExit(f"{path}:{i+1}: MinIO must remain at {baseline}")
        else:
            if ann["datasource"] != "pypi" or ann["versioning"] != "pep440":
                raise SystemExit(f"{path}:{i+1}: package {name} has inconsistent datasource/versioning")
            if ann["dep"] not in {"boto3", "minio"} or not value or channel.fullmatch(value):
                raise SystemExit(f"{path}:{i+1}: invalid PyPI annotation/value for {name}")
        found.append((str(path), ann["datasource"], ann["dep"], name))

# Every Docker container request must use the package's canonical constant.
for path in files:
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if image_field.search(line):
            raise SystemExit(f"{path}:{number}: container Image bypasses a canonical constant")

expected = {
    ("docker", "amazon/aws-cli"), ("docker", "python"),
    ("docker", "peakcom/s5cmd"), ("docker", "rclone/rclone"),
    ("docker", "restic/restic"), ("docker", "dxflrs/garage"),
    ("docker", "rustfs/rustfs"), ("docker", "chrislusf/seaweedfs"),
    ("docker", "quay.io/openbao/openbao"), ("docker", "ghcr.io/cosmian/kms"),
    ("docker", "valkey/valkey"), ("docker", "minio/minio"),
    ("docker", "quay.io/minio/minio"), ("pypi", "boto3"), ("pypi", "minio"),
}
actual = [(source, dep) for _, source, dep, _ in found]
for item in expected:
    count = actual.count(item)
    if count != 1:
        raise SystemExit(f"expected exactly one annotation for {item}, found {count}")
if set(actual) != expected:
    raise SystemExit(f"managed inventory mismatch: unexpected entries {sorted(set(actual) - expected)}")

print(f"test image pins: OK ({len(found)} annotated dependencies; canonical Image fields verified)")
PY
