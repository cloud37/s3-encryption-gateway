#!/usr/bin/env bash
#
# export-dashboard.sh — Render the Grafana dashboard JSON from Helm and
# write it to hack/dashboard.json.out for local verification.
#
# Usage:
#   bash hack/export-dashboard.sh [DATASOURCE_UID]
#
# If DATASOURCE_UID is given, it replaces the default "${DS_PROMETHEUS}"
# placeholder. Otherwise, the placeholder is preserved for manual editing.
#
# Output: hack/dashboard.json.out (gitignored by *.out rule)
#

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"
CHART="${REPO}/helm/s3-encryption-gateway"

# Determine the Datasource UID to inject.
# Priority: 1) CLI argument, 2) DS_PROMETHEUS env var, 3) Grafana placeholder.
if [ -n "${1:-}" ]; then
  DATASOURCE_UID="$1"
elif [ -n "${DS_PROMETHEUS:-}" ]; then
  DATASOURCE_UID="${DS_PROMETHEUS}"
else
  DATASOURCE_UID='${DS_PROMETHEUS}'
fi

OUTPUT="${HERE}/dashboard.json.out"

echo "=== Exporting Grafana dashboard JSON ==="

# Ensure chart dependencies are available (e.g. common helpers).
if ! helm dependency list "${CHART}" 2>/dev/null | grep -q 'ok'; then
  echo "Building Helm dependencies..."
  helm dependency build "${CHART}" >/dev/null
fi

# Render the ConfigMap template and extract the dashboard JSON.
#
# We use python3 to extract the nested YAML value because it is typically
# available and avoids requiring yq as a dependency.
echo "Rendering Helm template with monitoring.grafana.dashboard.enabled=true..."
RENDERED="$(helm template s3eg "${CHART}" \
  --set monitoring.grafana.dashboard.enabled=true \
  --set monitoring.grafana.dashboard.datasource="${DATASOURCE_UID}" \
  2>/dev/null)"

if [ -z "${RENDERED}" ]; then
  echo "ERROR: helm template produced no output. Check the chart path." >&2
  exit 1
fi

echo "Extracting dashboard JSON from ConfigMap data..."
DASHBOARD_JSON="$(
  echo "${RENDERED}" \
    | python3 -c "
import sys, yaml, json

docs = yaml.safe_load_all(sys.stdin)
for doc in docs:
    if doc and doc.get('kind') == 'ConfigMap':
        data = doc.get('data', {})
        for key, value in data.items():
            if key.endswith('.json'):
                print(value)
                sys.exit(0)
print('ERROR: no .json key found in ConfigMap data', file=sys.stderr)
sys.exit(1)
"
)"

echo "${DASHBOARD_JSON}" > "${OUTPUT}"

# Validate JSON.
python3 -m json.tool "${OUTPUT}" >/dev/null
echo "=== Dashboard exported and validated ==="
echo "  File:   ${OUTPUT}"
echo "  Import: Open Grafana → Dashboards → Import → Upload ${OUTPUT}"
echo ""
echo "NOTE: The dashboard uses the Prometheus datasource UID '${DATASOURCE_UID}'."
echo "      Update it in Grafana after import if your UID differs."
