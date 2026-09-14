#!/usr/bin/env bash
# V0.6-QA-1 Phase C — bench-macro.
#
# Runs the soak harness once against a single provider with the §3.2
# baseline fixture (10 workers, 60s, 25 QPS, 50 MiB objects, 10 MiB parts),
# and wraps the NDJSON stream emitted by SOAK_JSON_OUT with the §4.2
# envelope (schema_version, provider, provider_image, gateway_version,
# go_version, runner, generated_at, env, runs[]).
#
# Usage:
#   scripts/bench-macro.sh <provider>    # minio | garage | rustfs | seaweedfs
#
# Output:
#   docs/perf/v0.6-qa-1/macro-<provider>.json
#
# Env overrides for the runner identity line in the wrapper:
#   BENCH_RUNNER       default: github-ubuntu-latest (CI) or laptop-$USER
#   GATEWAY_VERSION    default: $(git describe)
#
# Required tools: go, jq, docker.

set -euo pipefail

cd "$(dirname "$0")/.."

provider="${1:-}"
case "$provider" in
  minio|garage|rustfs|seaweedfs) ;;
  "")
    echo "usage: $0 <minio|garage|rustfs|seaweedfs>" >&2
    exit 2
    ;;
  *)
    echo "unknown provider: $provider (expected minio|garage|rustfs|seaweedfs)" >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "bench-macro: jq is required; install with apt-get install -y jq" >&2
  exit 3
fi

outdir="docs/perf/v0.6-qa-1"
outfile="$outdir/macro-$provider.json"
mkdir -p "$outdir"

ndjson="$(mktemp -t "qa1-$provider-XXXXXX.ndjson")"
trap 'rm -f "$ndjson"' EXIT

# Skip all other providers + external for isolation (plan §3.2).
skip_env=()
for p in minio garage rustfs seaweedfs; do
  if [[ "$p" != "$provider" ]]; then
    skip_env+=("GATEWAY_TEST_SKIP_$(echo "$p" | tr '[:lower:]' '[:upper:]')=1")
  fi
done
skip_env+=("GATEWAY_TEST_SKIP_EXTERNAL=1")

runner="${BENCH_RUNNER:-${GITHUB_ACTIONS:+github-ubuntu-latest}}"
runner="${runner:-laptop-${USER:-unknown}}"
gateway_version="${GATEWAY_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

# Baseline fixture — matches §3.2.
soak_env=(
  SOAK_WORKERS=10
  SOAK_DURATION=60s
  SOAK_QPS=25
  SOAK_OBJECT_SIZE=52428800
  SOAK_CHUNK_SIZE=65536
  SOAK_PART_SIZE=10485760
  SOAK_JSON_OUT="$ndjson"
)

printf 'bench-macro(%s): running soak harness → %s\n' "$provider" "$ndjson" >&2

# Run only the two load tests; other conformance cases are not part of the
# baseline scope (plan §2.2 non-goal: "New benchmarks for ops other than
# those listed in §5"). -race is off (plan §3.1) so the numbers reflect
# production. -timeout 0 because the harness drives its own duration.
env "${skip_env[@]}" "${soak_env[@]}" go test \
  -tags=conformance \
  -timeout 0 -v \
  -run "TestConformance/$provider/Load_" \
  ./test/conformance/... \
  >&2

if [[ ! -s "$ndjson" ]]; then
  echo "bench-macro($provider): no JSON records emitted; check SOAK_JSON_OUT wiring" >&2
  exit 4
fi

printf 'bench-macro(%s): wrapping NDJSON → %s\n' "$provider" "$outfile" >&2

# Build the §4.2 envelope by folding the NDJSON stream into runs[].
# provider_image is best-effort — pulled from the container registry if
# the provider file carries a constant; defaults to empty string otherwise.
provider_image="$(
  case "$provider" in
    minio)     grep -hoE 'quay.io/minio/minio:[A-Za-z0-9._/:-]+' test/provider/minio.go 2>/dev/null | head -1 ;;
    garage)    grep -hoE 'dxflrs/garage:[A-Za-z0-9._/:-]+' test/provider/garage.go 2>/dev/null | head -1 ;;
    rustfs)    grep -hoE 'rustfs/rustfs:[A-Za-z0-9._/:-]+' test/provider/rustfs.go 2>/dev/null | head -1 ;;
    seaweedfs) grep -hoE 'chrislusf/seaweedfs:[A-Za-z0-9._/:-]+' test/provider/seaweedfs.go 2>/dev/null | head -1 ;;
  esac
)"
provider_image="${provider_image:-unknown}"

jq -s --arg provider "$provider" \
      --arg provider_image "$provider_image" \
      --arg gateway_version "$gateway_version" \
      --arg go_version "$(go version | awk '{print $3}')" \
      --arg runner "$runner" \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
   '{
      schema_version: "1",
      provider: $provider,
      provider_image: $provider_image,
      gateway_version: $gateway_version,
      go_version: $go_version,
      runner: $runner,
      generated_at: $generated_at,
      env: {
        SOAK_WORKERS: 10,
        SOAK_DURATION: "60s",
        SOAK_QPS: 25,
        SOAK_OBJECT_SIZE: 52428800,
        SOAK_CHUNK_SIZE: 65536,
        SOAK_PART_SIZE: 10485760
      },
      runs: .
    }' \
   "$ndjson" >"$outfile"

printf 'bench-macro(%s): wrote %s\n' "$provider" "$outfile" >&2
