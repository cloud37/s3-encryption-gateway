#!/bin/bash
set -euo pipefail

# Test script for Helm chart
# Validates that the chart renders correctly with different configurations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$SCRIPT_DIR")"

echo "Testing Helm chart: $CHART_DIR"

# Test 1: Default configuration with backend and auth credentials
echo ""
echo "Test 1: Default configuration with credentials"
helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password > /dev/null

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "BACKEND_ACCESS_KEY"; then
  echo "✓ BACKEND_ACCESS_KEY is present"
else
  echo "✗ BACKEND_ACCESS_KEY is missing"
  exit 1
fi

# Test 1b: backend TLS direct and valueFrom environment rendering.
echo ""
echo "Test 1b: backend TLS direct and valueFrom rendering"
TLS_DIRECT=$(helm template test "$CHART_DIR" \
  --set config.backend.tls.caFile.value=/etc/s3eg/ca.pem \
  --set-string config.backend.tls.insecureSkipVerify.value=false)
grep -q 'name: BACKEND_TLS_CA_FILE' <<<"$TLS_DIRECT" || { echo "✗ BACKEND_TLS_CA_FILE missing"; exit 1; }
grep -q 'name: BACKEND_TLS_INSECURE_SKIP_VERIFY' <<<"$TLS_DIRECT" || { echo "✗ BACKEND_TLS_INSECURE_SKIP_VERIFY missing"; exit 1; }
if grep -q '/etc/s3eg/ca.pem' <<<"$TLS_DIRECT"; then echo "✓ direct CA path rendered"; else echo "✗ direct CA path missing"; exit 1; fi
if grep -q 'BEGIN CERTIFICATE' <<<"$TLS_DIRECT"; then echo "✗ CA contents must not render"; exit 1; else echo "✓ CA contents not rendered"; fi
TLS_FROM=$(helm template test "$CHART_DIR" \
  --set config.backend.tls.caFile.value= \
  --set config.backend.tls.caFile.valueFrom.secretKeyRef.name=backend-ca \
  --set config.backend.tls.caFile.valueFrom.secretKeyRef.key=ca.pem \
  --set-string config.backend.tls.insecureSkipVerify.value=true)
grep -q 'name: BACKEND_TLS_CA_FILE' <<<"$TLS_FROM" || { echo "✗ valueFrom CA env missing"; exit 1; }
grep -q 'name: BACKEND_TLS_INSECURE_SKIP_VERIFY' <<<"$TLS_FROM" || { echo "✗ valueFrom skip env missing"; exit 1; }
echo "✓ direct and valueFrom TLS env names rendered"

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "BACKEND_SECRET_KEY"; then
  echo "✓ BACKEND_SECRET_KEY is present"
else
  echo "✗ BACKEND_SECRET_KEY is missing"
  exit 1
fi

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "GW_CRED_0_ACCESS_KEY"; then
echo "✓ GW_CRED_0_ACCESS_KEY is present"
else
  echo "✗ GW_CRED_0_ACCESS_KEY is missing"
  exit 1
fi

# Test 1c: SEC-49 spool budgets and ephemeral-storage render together.
echo ""
echo "Test 1c: SEC-49 spool limits and ephemeral-storage"
SEC49_OUTPUT=$(helm template sec49 "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password \
  --set-string config.tls.enabled.value=false \
  --set config.server.spoolDirectory.value=/var/lib/s3gw-spool \
  --set-string config.server.maxVerifiedSpoolBytes.value=123456789 \
  --set-string config.server.maxAggregateSpoolBytes.value=987654321 \
  --set ephemeralStorage.requests=12Gi \
  --set ephemeralStorage.limits=20Gi)
for expected in \
  'name: SERVER_SPOOL_DIRECTORY' \
  'name: SERVER_MAX_VERIFIED_SPOOL_BYTES' \
  'name: SERVER_MAX_AGGREGATE_SPOOL_BYTES' \
  'ephemeral-storage: "12Gi"' \
  'ephemeral-storage: "20Gi"' \
  '/var/lib/s3gw-spool' \
  '123456789' \
  '987654321'; do
  if grep -q "$expected" <<<"$SEC49_OUTPUT"; then
    echo "✓ SEC-49 rendered: $expected"
  else
    echo "✗ SEC-49 rendering missing: $expected"
    exit 1
  fi
done

# Test 2: existingCredentialsSecret rendering
echo ""
echo "Test 2: existingCredentialsSecret"
helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password > /dev/null

if helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "AUTH_CREDENTIALS_FILE"; then
  echo "✓ AUTH_CREDENTIALS_FILE is present"
else
  echo "✗ AUTH_CREDENTIALS_FILE is missing"
  exit 1
fi

if helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "GW_CRED_0_ACCESS_KEY"; then
  echo "✗ GW_CRED_0_ACCESS_KEY should not be present with existingCredentialsSecret"
  exit 1
else
  echo "✓ GW_CRED_0_ACCESS_KEY correctly excluded"
fi

# Test 3: Validate chart linting
echo ""
echo "Test 3: Helm chart linting"
if helm lint "$CHART_DIR" > /dev/null 2>&1; then
  echo "✓ Chart passes linting"
else
  echo "✗ Chart linting failed"
  helm lint "$CHART_DIR"
  exit 1
fi

# Test 4: Schema validation — helm lint with a known-bad values file must fail
echo ""
echo "Test 4: Schema validation rejects invalid values"
BAD_VALUES="$CHART_DIR/tests/schema/bad-replica-string.yaml"
if helm lint "$CHART_DIR" -f "$BAD_VALUES" > /dev/null 2>&1; then
  echo "✗ helm lint should have FAILED for bad values: $BAD_VALUES"
  exit 1
else
  echo "✓ helm lint correctly rejected invalid replicaCount type (string instead of integer)"
fi

BAD_TRACK="$CHART_DIR/tests/schema/bad-track-with-valkey.yaml"
if helm lint "$CHART_DIR" -f "$BAD_TRACK" > /dev/null 2>&1; then
  echo "✗ helm lint should have FAILED for bad values: $BAD_TRACK"
  exit 1
else
  echo "✓ helm lint correctly rejected track+valkey.enabled=true invariant violation (I1)"
fi

echo ""
echo "All tests passed!"
