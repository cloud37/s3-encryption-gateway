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

# The read-only root filesystem still needs a writable spool for signed GETs.
echo ""
echo "Test 1d: default spool and existing /tmp mount"
DEFAULT_SPOOL=$(helm template spool "$CHART_DIR" --show-only templates/deployment.yaml)
grep -q 'name: SERVER_SPOOL_DIRECTORY' <<<"$DEFAULT_SPOOL" || { echo "✗ spool env missing"; exit 1; }
grep -q 'value: "/tmp"' <<<"$DEFAULT_SPOOL" || { echo "✗ spool path missing"; exit 1; }
grep -q 'mountPath: /tmp' <<<"$DEFAULT_SPOOL" || { echo "✗ /tmp mount missing"; exit 1; }
grep -q 'emptyDir: {}' <<<"$DEFAULT_SPOOL" || { echo "✗ default spool volume missing"; exit 1; }
if [[ $(grep -c 'name: gateway-spool' <<<"$DEFAULT_SPOOL") -ne 2 ]]; then
  echo "✗ default spool mount and volume must match"
  exit 1
fi
CUSTOM_TMP=$(helm template spool "$CHART_DIR" --show-only templates/deployment.yaml \
  --set extraVolumeMounts[0].name=operator-tmp \
  --set extraVolumeMounts[0].mountPath=/tmp \
  --set extraVolumes[0].name=operator-tmp \
  --set extraVolumes[0].emptyDir.sizeLimit=1Gi)
if grep -q 'name: gateway-spool' <<<"$CUSTOM_TMP"; then
  echo "✗ custom /tmp mount conflicts with default spool volume"
  exit 1
fi
if [[ $(grep -c 'mountPath: /tmp' <<<"$CUSTOM_TMP") -ne 1 ]]; then
  echo "✗ custom /tmp mount must render only once"
  exit 1
fi
grep -q 'name: operator-tmp' <<<"$CUSTOM_TMP" || { echo "✗ custom /tmp volume missing"; exit 1; }
echo "✓ default spool and custom /tmp mount rendered without conflicts"

# Gateway CORS: durable shared Valkey requirement and JSON-array environment encoding.
echo ""
echo "Test 1e: gateway CORS Valkey and fallback"
CORS_OUTPUT=$(helm template cors "$CHART_DIR" \
  --set-string config.cors.mode.value=gateway \
  --set valkey.enabled=true \
  --set-json 'config.cors.fallback.allowedOrigins.value=["https://app.example.com"]' \
  --set-json 'config.cors.fallback.allowedMethods.value=["GET","PUT"]' \
  --set-json 'config.cors.fallback.allowedHeaders.value=["content-type","x-amz-*"]' \
  --set-json 'config.cors.fallback.exposeHeaders.value=["ETag"]' \
  --set-string config.cors.allowCredentials.value=true \
  --set-string config.cors.fallback.maxAgeSeconds.value=900)
grep -q 'name: CORS_MODE' <<<"$CORS_OUTPUT" || { echo "✗ CORS_MODE missing"; exit 1; }
grep -q 'value: "gateway"' <<<"$CORS_OUTPUT" || { echo "✗ gateway mode missing"; exit 1; }
grep -q 'name: CORS_FALLBACK_ALLOWED_ORIGINS' <<<"$CORS_OUTPUT" || { echo "✗ CORS origin fallback missing"; exit 1; }
grep -Fq 'value: "[\"https://app.example.com\"]"' <<<"$CORS_OUTPUT" || { echo "✗ CORS array not JSON encoded"; exit 1; }
for expected in CORS_ALLOW_CREDENTIALS CORS_FALLBACK_ALLOWED_METHODS CORS_FALLBACK_ALLOWED_HEADERS CORS_FALLBACK_EXPOSE_HEADERS CORS_FALLBACK_MAX_AGE_SECONDS; do
  grep -q "name: $expected" <<<"$CORS_OUTPUT" || { echo "✗ $expected missing"; exit 1; }
done
grep -Fq 'value: "true"' <<<"$CORS_OUTPUT" || { echo "✗ CORS credentials missing"; exit 1; }
grep -Fq 'value: "900"' <<<"$CORS_OUTPUT" || { echo "✗ CORS max-age missing"; exit 1; }
if helm template cors "$CHART_DIR" --set config.cors.mode.value=gateway --set valkey.enabled=false > /dev/null 2>&1; then
  echo "✗ schema-only gateway Valkey invariant must reject missing Valkey"; exit 1
fi
if helm template cors "$CHART_DIR" --set valkey.enabled=false \
  --set config.cors.mode.valueFrom.secretKeyRef.name=cors-mode \
  --set config.cors.mode.valueFrom.secretKeyRef.key=mode > /dev/null 2>&1; then
  echo "✗ indirect CORS mode must conservatively require Valkey"; exit 1
fi
FROM_OUTPUT=$(helm template cors "$CHART_DIR" \
  --set-string config.cors.mode.value=gateway --set valkey.enabled=false \
  --set config.multipartState.valkey.addr.value=valkey.example:6379 \
  --set config.cors.fallback.allowedOrigins.valueFrom.secretKeyRef.name=cors-config \
  --set config.cors.fallback.allowedOrigins.valueFrom.secretKeyRef.key=origins)
grep -q 'secretKeyRef:' <<<"$FROM_OUTPUT" || { echo "✗ CORS valueFrom missing"; exit 1; }
grep -q 'name: CORS_MODE' <<<"$FROM_OUTPUT" || { echo "✗ CORS mode valueFrom env missing"; exit 1; }
grep -q 'name: CORS_FALLBACK_ALLOWED_ORIGINS' <<<"$FROM_OUTPUT" || { echo "✗ CORS valueFrom origin env missing"; exit 1; }
grep -q 'name: VALKEY_ADDR' <<<"$FROM_OUTPUT" || { echo "✗ external Valkey addr env missing"; exit 1; }
if helm template cors "$CHART_DIR" --set-string config.cors.mode.value=gateway --set valkey.enabled=false > /dev/null 2>&1; then
  echo "✗ gateway CORS without Valkey should fail"; exit 1
fi
if helm template cors "$CHART_DIR" --set valkey.enabled=true --set-string config.cors.mode.value=invalid > /dev/null 2>&1; then
  echo "✗ invalid CORS mode should fail"; exit 1
fi
MODE_FROM_OUTPUT=$(helm template cors "$CHART_DIR" --set valkey.enabled=true \
  --set config.cors.mode.valueFrom.secretKeyRef.name=cors-mode \
  --set config.cors.mode.valueFrom.secretKeyRef.key=mode)
grep -q 'name: CORS_MODE' <<<"$MODE_FROM_OUTPUT" || { echo "✗ CORS mode valueFrom env missing"; exit 1; }
grep -q 'secretKeyRef:' <<<"$MODE_FROM_OUTPUT" || { echo "✗ CORS mode valueFrom ref missing"; exit 1; }
MODE_EXTERNAL_OUTPUT=$(helm template cors "$CHART_DIR" --set valkey.enabled=false \
  --set config.cors.mode.valueFrom.secretKeyRef.name=cors-mode \
  --set config.cors.mode.valueFrom.secretKeyRef.key=mode \
  --set config.multipartState.valkey.addr.value=valkey.example:6379)
grep -q 'name: VALKEY_ADDR' <<<"$MODE_EXTERNAL_OUTPUT" || { echo "✗ indirect mode with direct external Valkey addr must render"; exit 1; }
MODE_CONFLICT_OUTPUT=$(helm template cors "$CHART_DIR" --set valkey.enabled=false \
  --set-string config.cors.mode.value=passthrough \
  --set config.cors.mode.valueFrom.secretKeyRef.name=cors-mode \
  --set config.cors.mode.valueFrom.secretKeyRef.key=mode \
  --set config.multipartState.valkey.addr.value=valkey.example:6379)
grep -q 'name: CORS_MODE' <<<"$MODE_CONFLICT_OUTPUT" || { echo "✗ conflicting indirect mode did not render"; exit 1; }
if grep -A3 -B1 'name: CORS_MODE' <<<"$MODE_CONFLICT_OUTPUT" | grep -q 'value: "passthrough"'; then
  echo "✗ mode valueFrom must take precedence over direct value"; exit 1
fi
if helm template cors "$CHART_DIR" --set valkey.enabled=false \
  --set-string config.cors.mode.value=passthrough \
  --set config.cors.mode.valueFrom.secretKeyRef.name=cors-mode \
  --set config.cors.mode.valueFrom.secretKeyRef.key=mode > /dev/null 2>&1; then
  echo "✗ valueFrom precedence must not bypass the Valkey guard"; exit 1
fi
if helm template cors "$CHART_DIR" --set-string config.cors.mode.value=gateway --set valkey.enabled=false --set-json 'config.cors.fallback.allowedOrigins.value="https://app.example.com"' --set config.multipartState.valkey.addr.value=valkey.example:6379 > /dev/null 2>&1; then
  echo "✗ CORS origin array must reject scalar string"; exit 1
fi
if helm template cors "$CHART_DIR" --set-string config.cors.mode.value=gateway --set valkey.enabled=false --set config.multipartState.valkey.addr.value=valkey.example:6379 --set config.cors.allowCredentials.value=true > /dev/null 2>&1; then
  echo "✗ CORS credentials must reject boolean"; exit 1
fi
if helm template cors "$CHART_DIR" --set-string config.cors.mode.value=gateway --set valkey.enabled=false --set config.multipartState.valkey.addr.value=valkey.example:6379 --set-string config.cors.fallback.maxAgeSeconds.value=-1 > /dev/null 2>&1; then
  echo "✗ CORS negative max-age must fail schema validation"; exit 1
fi
if helm template cors "$CHART_DIR" --set-json 'config.cors.fallback.allowedOrigins.value=["https://app.example.com"]' > /dev/null 2>&1; then
  echo "✗ passthrough mode must reject fallback settings"; exit 1
fi
echo "✓ gateway CORS renders JSON arrays/valueFrom and rejects missing Valkey or invalid mode"

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
