# OPS_DEPLOYMENT.md — Progressive Delivery Runbook

> **Single authoritative source for blue/green and canary deployments of
> the S3 Encryption Gateway on Kubernetes.**
>
> Scope: Helm chart v0.6+. Implemented by V0.6-OPS-1.
> See `docs/plans/V0.6-OPS-1-plan.md` for design rationale and references.

---

## Table of Contents

1. [Overview — when to use which strategy](#1-overview)
2. [Stateful Invariants — read this before any cutover](#2-stateful-invariants)
3. [Blue/Green Recipe](#3-bluegreen-recipe)
4. [Canary Recipe (Traefik)](#4-canary-recipe-traefik)
5. [Interaction with Key Rotation](#5-interaction-with-key-rotation)
6. [Interaction with Encrypted Multipart Uploads (Valkey)](#6-interaction-with-encrypted-multipart-uploads)
7. [Interaction with the FIPS Build](#7-interaction-with-the-fips-build)
8. [Observability — per-track dashboards](#8-observability)
9. [Troubleshooting — top 5 footguns](#9-troubleshooting)
10. [Gateway API appendix (portable, controller-agnostic)](#10-gateway-api-appendix)
11. [Optional: Argo Rollouts / Flagger overlay](#11-optional-argo-rollouts--flagger)
12. [Migration note for ingress-nginx operators](#12-migration-note-for-ingress-nginx-operators)
13. [References](#13-references)

---

## 1. Overview

### When to use which strategy

| Strategy | Use when | Traffic shift | Rollback time |
|---|---|---|---|
| **Rolling update** (chart default) | Backward-compatible code change with no schema or API break | Gradual, pod-by-pod | ~30 s |
| **Blue/Green** | Need instant, atomic flip; want to pre-warm the new version; data-plane break is tolerable during a short propagation window | Atomic (Service selector patch) | ~1 s API + 5–30 s kube-proxy |
| **Canary** | Risk-averse rollout; new version is production-untested; want to validate SLIs against real traffic before committing | Progressive (5 → 25 → 50 → 100) | ~1 s (Traefik weight patch) |
| **Neither** | Dev / staging / single-replica deployment | — | — |

**Key reference**: Ibryam & Huss, *Kubernetes Patterns, 2nd Ed.* Ch. 3 "Declarative
Deployment" — the authoritative taxonomy of Kubernetes release strategies.

---

## 2. Stateful Invariants

> **Read this section before any cutover or canary promotion. Violating
> these invariants causes data loss or availability incidents.**

The S3 Encryption Gateway is not a stateless proxy. It carries two pieces
of state that survive across pod restarts and traffic flips:

### 2.1 Active Key Version Parity

Both colours/tracks **must** wrap newly-written Data Encryption Keys (DEKs)
against the same active `key_version` in the KMS provider (e.g. Cosmian KMS).

- Objects written by blue are stored with a DEK wrapped against key version
  `N`. If green starts with key version `N+1` as the active wrapping key,
  green can still **read** blue's objects (via the `dualReadWindow` setting),
  but the risk of accidentally advancing the active key version before cutover
  is a foot-gun.
- **Rule: key rotation (advancing the active version) happens on green AFTER
  the traffic flip completes, never before.** See §5.

**Verification:**

```bash
scripts/verify-key-parity.sh gw-blue gw-green
```

The script diffs the `KEY_MANAGER_PROVIDER` and `COSMIAN_KMS_KEYS` env vars
across both releases' rendered configmaps. Exit code 0 = safe to proceed.

### 2.2 Encrypted MPU State Store (Valkey) Must Be Shared

Multipart upload state (`UploadPart` manifests) is stored in Valkey under
the key `mpu:<sha256(uploadId)>` (ADR 0009). If a client starts a
`CreateMultipartUpload` on blue and the traffic flip happens before
`CompleteMultipartUpload`, the subsequent `UploadPart` or `CompleteMPU`
request will land on green — and green **must** see the same Valkey state
or the upload aborts with `NoSuchUpload`.

**Rule: both colours/tracks MUST share a single Valkey cluster. The per-release
Valkey subchart (`valkey.enabled: true`) is WRONG for blue/green and canary
topologies. Set `valkey.enabled: false` on all releases and supply a shared
external Valkey address.**

The chart enforces this at render time: setting `track: blue` with
`valkey.enabled: true` produces a `helm template` failure:

```
Error: ... valkey.enabled must be false and config.multipartState.valkey.addr must
point to a shared external Valkey cluster.
```

See §6 for the shared Valkey setup steps and `docs/examples/bluegreen/external-valkey.yaml`
for a minimal standalone Valkey manifest.

### 2.3 Readiness + Connection Draining

The Service selector flip (§3.8) is atomic from the Kubernetes API server's
point of view but kube-proxy propagates the iptables/IPVS changes
asynchronously. Propagation tail is typically 5–30 s per node (Burns et al.,
*Kubernetes Best Practices, 2nd Ed.* Ch. 4).

In-flight S3 requests on the old colour — long `CopyObject`, 5 GiB
`UploadPart`, 100 MiB range GET — need to drain gracefully.

**Rule: set `terminationGracePeriodSeconds` ≥ 99th-p request duration + a
`preStop` sleep ≥ kube-proxy propagation tail (10 s minimum).**

The example values files bake in:

```yaml
terminationGracePeriodSeconds: 60
lifecycle:
  preStop:
    exec:
      command: ["sh", "-c", "sleep 10"]
```

Tune these values for your workload. For workloads with large objects or
slow `CopyObject` operations, increase to 120–300 s.

### 2.4 Precondition Checklist (run before every cutover)

- [ ] Both releases' Deployments are `Available`.
- [ ] `scripts/verify-key-parity.sh` exits 0.
- [ ] Both releases point at the **same** external Valkey address.
- [ ] New release has been smoke-tested via `kubectl port-forward`.
- [ ] Analysis window on the new release (read replicas, staged traffic, or
      load test) shows no elevated error rate or latency.
- [ ] PodDisruptionBudgets are in place on both colours.
- [ ] `terminationGracePeriodSeconds` and `preStop` sleep are configured.

---

## 3. Blue/Green Recipe

### Architecture

```
                    ┌────────────────────────────┐
                    │  gateway Service           │
                    │  (operator-owned,          │
                    │   selector: track=blue)    │
                    └─────────────┬──────────────┘
                                  │
           ┌──────────────────────┴──────────────────────┐
           │                                             │
  ┌────────▼──────────┐                      ┌──────────▼────────┐
  │ Release: gw-blue  │                      │ Release: gw-green │
  │ track=blue        │                      │ track=green       │
  │ valkey.enabled=F  │                      │ valkey.enabled=F  │
  └────────┬──────────┘                      └──────────┬────────┘
           │                                             │
           └──────────────────┬──────────────────────────┘
                              │
               ┌──────────────▼───────────────┐
               │ External Valkey              │
               │ (shared, cluster-scoped)     │
               └──────────────────────────────┘
```

### Step-by-step procedure

**Step 1 — Deploy or verify shared external Valkey**

```bash
# Option A: use the provided minimal manifest
kubectl create namespace mpu-state --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f docs/examples/bluegreen/external-valkey.yaml

# Option B: use an existing Valkey cluster — just note its address.

# Verify connectivity:
kubectl -n mpu-state run valkey-test --image=valkey/valkey:7.2-alpine \
  --rm -it --restart=Never -- valkey-cli -h valkey-shared ping
# Expected: PONG
```

**Step 2 — Install the blue release**

```bash
helm install gw-blue helm/s3-encryption-gateway \
  --namespace s3-gateway \
  --values helm/s3-encryption-gateway/examples/values-blue.yaml \
  --set config.backend.endpoint.value=https://your-backend.example.com \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379
```

**Step 3 — Verify blue is Ready**

```bash
kubectl -n s3-gateway wait --for=condition=available --timeout=120s \
  deployment/gw-blue-s3-encryption-gateway
kubectl -n s3-gateway get pods -l track=blue
```

**Step 4 — Deploy the shared operator-owned Service**

```bash
# Adjust namespace in service.yaml if needed, then:
kubectl apply -f docs/examples/bluegreen/service.yaml -n s3-gateway

# Verify it selects blue pods:
kubectl -n s3-gateway get endpointslices -l kubernetes.io/service-name=gateway
```

**Step 5 — Install the green release**

The green release runs the new image version but must use the **same** active
key version and shared Valkey as blue.

```bash
helm install gw-green helm/s3-encryption-gateway \
  --namespace s3-gateway \
  --values helm/s3-encryption-gateway/examples/values-green.yaml \
  --set image.tag=0.10.1 \   # new version
  --set config.backend.endpoint.value=https://your-backend.example.com \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379
```

**Step 6 — Key parity check**

```bash
scripts/verify-key-parity.sh gw-blue gw-green
# Must exit 0. If it fails, the KEY_MANAGER_PROVIDER or COSMIAN_KMS_KEYS
# env vars differ between releases. Fix the discrepancy before proceeding.
```

**Step 7 — Smoke test green directly**

```bash
kubectl -n s3-gateway port-forward deployment/gw-green-s3-encryption-gateway 9090:8080 &
# Run your S3 smoke test against localhost:9090
aws s3 ls s3://your-bucket --endpoint-url http://localhost:9090
kill %1
```

**Step 8 — Cutover**

```bash
docs/examples/bluegreen/cutover.sh green
# Or manually:
kubectl -n s3-gateway patch service gateway \
  -p '{"spec":{"selector":{"app.kubernetes.io/name":"s3-encryption-gateway","track":"green"}}}'
```

**Step 9 — Observe analysis window (≥ 15 min)**

```prometheus
# Error rate per track:
rate(s3_gateway_requests_total{track="green",status=~"5.."}[5m])
  / rate(s3_gateway_requests_total{track="green"}[5m])

# p99 latency per track:
histogram_quantile(0.99,
  rate(s3_gateway_request_duration_seconds_bucket{track="green"}[5m]))
```

**Step 10 — Rollback if needed**

```bash
docs/examples/bluegreen/cutover.sh blue
```

**Step 11 — Retire the old colour after soak**

```bash
helm uninstall gw-blue --namespace s3-gateway
```

---

## 4. Canary Recipe (Traefik)

### Prerequisites

- Traefik **≥ v3.0** is the cluster ingress controller.
  - v3.0 changed the CRD API group from `traefik.containo.us` to `traefik.io`.
    The chart emits `traefik.io/v1alpha1`; pre-v3 clusters must upgrade Traefik first.
- Both `gw-stable` and `gw-canary` chart releases.
- Shared external Valkey (same requirement as blue/green — see §2.2).

### Architecture

```
          ┌──────────────────────────────────┐
          │ IngressRoute (operator-owned)    │
          │ Host(`s3.example.com`)           │
          │  → kind: TraefikService          │
          └──────────────────┬───────────────┘
                             │
          ┌──────────────────▼───────────────┐
          │ TraefikService (kind: Weighted)  │
          │  gw-stable  weight: 95           │
          │  gw-canary  weight:  5           │
          │  sticky cookie: gw-pin           │
          └───────────┬──────────────────────┘
                      │
        ┌─────────────┴────────────┐
   ┌────▼────────────┐    ┌────────▼────────┐
   │ Release: stable │    │ Release: canary │
   │ chart v0.5.x    │    │ chart v0.6.x-rc │
   └────────┬────────┘    └────────┬────────┘
            └──────────┬───────────┘
                       │
          ┌────────────▼────────────┐
          │ External Valkey        │
          │ (shared)               │
          └────────────────────────┘
```

### Step-by-step procedure

**Step 1 — Stable release: ensure it uses its own Service and no Ingress**

If the stable release currently uses `ingress.enabled: true`, update it:

```bash
helm upgrade gw-stable helm/s3-encryption-gateway \
  --namespace s3-gateway \
  --values helm/s3-encryption-gateway/examples/values-canary-stable.yaml \
  --set config.backend.endpoint.value=https://your-backend.example.com \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379
```

**Step 2 — Install the canary release**

```bash
helm install gw-canary helm/s3-encryption-gateway \
  --namespace s3-gateway \
  --values helm/s3-encryption-gateway/examples/values-canary-canary.yaml \
  --set image.tag=0.10.1-rc1 \   # candidate version
  --set config.backend.endpoint.value=https://your-backend.example.com \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379
```

**Step 3 — Apply the operator-owned Traefik manifests**

Edit `docs/examples/canary/traefikservice.yaml` and `ingressroute.yaml` to
use your actual Service names, namespace, and hostname, then:

```bash
kubectl apply -f docs/examples/canary/traefikservice.yaml -n s3-gateway
kubectl apply -f docs/examples/canary/ingressroute.yaml -n s3-gateway
```

**Step 4 — Verify both releases are Ready and the split is active**

```bash
kubectl -n s3-gateway get deployment -l app.kubernetes.io/name=s3-encryption-gateway
kubectl -n s3-gateway get traefikservice,ingressroute
```

**Step 5 — Observe canary SLIs during soak window**

```prometheus
# Canary error rate:
rate(s3_gateway_requests_total{track="canary",status=~"5.."}[5m])
  / rate(s3_gateway_requests_total{track="canary"}[5m])

# Canary p99 latency:
histogram_quantile(0.99,
  rate(s3_gateway_request_duration_seconds_bucket{track="canary"}[5m]))
```

If metrics look good, promote progressively:

**Step 6 — Progressive weight promotion**

```bash
docs/examples/canary/promote.sh 25   # 25 % canary
# Wait for soak window; re-check SLIs.

docs/examples/canary/promote.sh 50   # 50 % canary
# Wait for soak window; re-check SLIs.

docs/examples/canary/promote.sh 100  # full promotion
```

**Step 7 — Rollback if SLIs degrade**

```bash
# Non-emergency (graceful, snaps weight to 0):
docs/examples/canary/promote.sh --rollback

# Emergency (immediately snaps to 0, then removes the canary release):
docs/examples/canary/rollback.sh
```

**Step 8 — Role swap after full promotion**

After `promote.sh 100` and a final soak:

1. Upgrade `gw-stable` to the new image (the version that was canary):
   ```bash
   helm upgrade gw-stable helm/s3-encryption-gateway \
     --namespace s3-gateway \
     --values helm/s3-encryption-gateway/examples/values-canary-stable.yaml \
     --set image.tag=0.10.1-rc1
   ```
2. Update `docs/examples/canary/traefikservice.yaml` weights back to 100/0
   (stable=100, canary=0) and apply.
3. `helm uninstall gw-canary --namespace s3-gateway`
4. Advance the KMS key version if desired (see §5).

---

## 5. Interaction with Key Rotation

Key rotation (CFG-1) advances the active KMS key version used to wrap new
DEKs. It is a two-phase operation: drain old-key-version writes → promote
new version → old version becomes a read-only dual-read window entry.

**Rule: rotation happens on the new colour/track AFTER the traffic flip
(blue/green) or AFTER full promotion to 100 % (canary). Never before.**

Why: if green advances its active key version before the flip, blue continues
to wrap DEKs against the now-older version. This is technically safe
(dual-read window covers it) but causes confusion if blue needs to roll back
after the flip — blue would be writing DEKs against an older key that has
been superseded on green.

Post-cutover rotation procedure (see `docs/ADMIN_API.md` for the admin API
endpoints):

```bash
# On the new colour (green / canary after full promotion):
# 1. Trigger key rotation via the admin API:
curl -X POST https://127.0.0.1:8081/admin/keys/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 2. Verify the active version advanced:
curl https://127.0.0.1:8081/admin/keys/status \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 3. The old colour's dual-read window covers old DEKs automatically.
```

Cross-reference: ADR 0007 "Admin API & Key Rotation".

---

## 6. Interaction with Encrypted Multipart Uploads

The gateway encrypts multipart upload (MPU) state in Valkey (ADR 0009). Each
`CreateMultipartUpload` allocates a Valkey key `mpu:<sha256(uploadId)>` that
stores the encrypted manifest. `UploadPart` and `CompleteMultipartUpload`
operations mutate this key.

**For blue/green and canary:**

- A single S3 SDK session can issue `CreateMultipartUpload` on the old colour
  and `UploadPart` on the new colour (after the flip/promotion). Both must
  see the same Valkey state — hence the shared external Valkey requirement.
- Traefik's sticky cookie (`gw-pin`) in the canary topology pins a given
  session to one backend for the duration of its TCP connection pool lifetime
  (S3 SDKs keep connections alive for minutes). This reduces Valkey round-trips
  but **correctness does not depend on stickiness** — only shared Valkey is
  required.

**Shared Valkey setup:**

Option A — minimal standalone StatefulSet (dev/low-traffic):
```bash
kubectl apply -f docs/examples/bluegreen/external-valkey.yaml
```

Option B — production Valkey Cluster or Sentinel (recommended for HA):
Deploy via your organisation's Valkey/Redis chart and set:
```yaml
config:
  multipartState:
    valkey:
      addr:
        value: "valkey-cluster.your-ns.svc.cluster.local:6379"
      tls:
        enabled:
          value: "true"
        caFile:
          value: "/etc/valkey-tls/ca.crt"
```

Cross-reference: ADR 0009 "Encrypted Multipart Uploads".

---

## 7. Interaction with the FIPS Build

Both colours/tracks in a blue/green or canary deployment **must use the same
build profile**. Running one colour on the standard image and the other on the
FIPS image (`-tags=fips`, `Dockerfile.fips`) is unsupported and can produce
decrypt failures if the FIPS build selects a different AES-GCM implementation
path.

**Verification:**

```bash
# Check image digests / tags for both releases:
kubectl -n s3-gateway get pods -l app.kubernetes.io/name=s3-encryption-gateway \
  -o jsonpath='{range .items[*]}{.metadata.labels.track}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

Both lines should use the same image base tag (`...:v0.6.x` vs.
`...:v0.6.x-fips`).

Cross-reference: ADR 0005 "FIPS Profile".

---

## 8. Observability — Per-Track Dashboards

The `track` label is propagated to:

- Pod labels → captured by `ServiceMonitor` and `PodMonitor` via the chart's
  relabel configuration.
- Prometheus metric labels → use `{track="blue"}` / `{track="canary"}` in
  PromQL queries.

### Per-track Prometheus queries

```prometheus
# Request rate by track:
rate(s3_gateway_requests_total{track="canary"}[5m])

# Error rate by track:
rate(s3_gateway_requests_total{track="canary",status=~"5.."}[5m])
  / rate(s3_gateway_requests_total{track="canary"}[5m])

# p99 latency by track:
histogram_quantile(0.99,
  rate(s3_gateway_request_duration_seconds_bucket{track="canary"}[5m]))

# Active MPU sessions (shared Valkey — not per-track):
s3_gateway_multipart_active_uploads_total
```

### Grafana dashboard variable

Add a `track` variable to your Grafana dashboard:

```
Label: Track
Type: Query
Query: label_values(s3_gateway_requests_total, track)
```

Then use `{track=~"$track"}` in all panel queries.

---

## 9. Troubleshooting

### 9.1 Service selector didn't flip (kube-proxy cache)

**Symptom:** Traffic still goes to the old colour 30+ seconds after the patch.

**Diagnosis:**
```bash
# Check if the endpointslice shows the new colour's pods:
kubectl -n s3-gateway get endpointslices \
  -l kubernetes.io/service-name=gateway \
  -o jsonpath='{range .items[*].endpoints[*]}{.targetRef.name}{"\t"}{.conditions.ready}{"\n"}{end}'

# Check if the Service selector was patched:
kubectl -n s3-gateway get service gateway \
  -o jsonpath='{.spec.selector}'
```

**Fix:** kube-proxy propagates asynchronously. Wait up to 60 s. If it still
doesn't flip, check that both colours' pods actually have the `track` label:

```bash
kubectl -n s3-gateway get pods -l app.kubernetes.io/name=s3-encryption-gateway \
  --show-labels | grep track
```

### 9.2 Multipart upload fails after cutover (`NoSuchUpload`)

**Symptom:** `NoSuchUpload` errors from S3 clients after a traffic flip.

**Root cause:** The new colour is not pointing at the same Valkey cluster as
the old colour, or the Valkey address is wrong.

**Diagnosis:**
```bash
# Check the VALKEY_ADDR env var on both releases:
kubectl -n s3-gateway get pods -l track=green \
  -o jsonpath='{.items[0].spec.containers[0].env}' | \
  python3 -c "import sys,json; e=json.load(sys.stdin); print([x for x in e if x['name']=='VALKEY_ADDR'])"
```

Both colours must show the same Valkey address. If they differ, update the
values file and run `helm upgrade`.

### 9.3 Decrypt fails on the new colour reading the old colour's objects

**Symptom:** HTTP 500 or `DecryptionError` on GET requests after cutover.

**Root cause:** The active `key_version` in the KMS provider differs between
the two releases. Green is trying to unwrap DEKs with a different key than
blue used to wrap them.

**Diagnosis:**
```bash
scripts/verify-key-parity.sh gw-blue gw-green
```

**Fix:** Update the values file to align key versions. The `dualReadWindow`
setting (default 1) means green can read blue's objects if the key version
difference is ≤ 1 — but only if the provider and key IDs are the same.

### 9.4 Client SDK retries storm during cutover

**Symptom:** Error rate spike lasting 5–30 s immediately after the selector
patch; clients see connection refused or reset errors.

**Root cause:** `terminationGracePeriodSeconds` is too short. Pods on the old
colour terminate before in-flight requests finish.

**Fix:** Increase `terminationGracePeriodSeconds` and add a `preStop` sleep:

```yaml
terminationGracePeriodSeconds: 120   # increase for large-object workloads
lifecycle:
  preStop:
    exec:
      command: ["sh", "-c", "sleep 30"]   # match your kube-proxy propagation tail
```

### 9.5 Traefik canary not splitting traffic

**Symptom:** 100 % of traffic goes to one backend despite the weighted TraefikService.

**Causes and fixes:**

1. **TraefikService name mismatch.** The IngressRoute `services[].name` must
   match the `TraefikService` metadata name exactly:
   ```bash
   kubectl -n s3-gateway get traefikservice,ingressroute
   ```

2. **Weights don't sum to 100.** The chart guard rejects this at render time
   if you use the chart-managed TraefikService, but the operator-owned manifest
   has no guard. Check:
   ```bash
   kubectl -n s3-gateway get traefikservice gateway-weighted \
     -o jsonpath='{.spec.weighted.services[*].weight}'
   ```

3. **Service selectors don't match any pods.** The TraefikService references
   Kubernetes Services by name; those Services must have endpoints:
   ```bash
   kubectl -n s3-gateway get endpoints gw-stable-s3-encryption-gateway gw-canary-s3-encryption-gateway
   ```

4. **Traefik version < v3.0.** This chart emits `traefik.io/v1alpha1` (v3+ API
   group). Pre-v3 Traefik used `traefik.containo.us/v1alpha1` and will ignore
   resources with the new group. Upgrade Traefik first.
   ```bash
   kubectl -n traefik get deployment traefik \
     -o jsonpath='{.spec.template.spec.containers[0].image}'
   ```

---

## 10. Gateway API Appendix

For operators standardised on the Kubernetes Gateway API (Traefik, Envoy
Gateway, Cilium, Istio, Contour — all conformant), the portable alternative
to the Traefik `TraefikService` is a single `HTTPRoute` with weighted
`backendRefs`:

```yaml
# docs/examples/gateway-api/httproute.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: gateway
  namespace: s3-gateway
spec:
  parentRefs:
    - name: public-gateway
  hostnames: ["s3.example.com"]
  rules:
    - backendRefs:
        - name: gw-stable-s3-encryption-gateway
          port: 80
          weight: 95
        - name: gw-canary-s3-encryption-gateway
          port: 80
          weight: 5
```

Apply:
```bash
kubectl apply -f docs/examples/gateway-api/httproute.yaml -n s3-gateway
```

Promote by patching the `weight` fields directly:
```bash
kubectl patch httproute gateway -n s3-gateway --type=json \
  -p '[
    {"op":"replace","path":"/spec/rules/0/backendRefs/0/weight","value":50},
    {"op":"replace","path":"/spec/rules/0/backendRefs/1/weight","value":50}
  ]'
```

**All stateful invariants from §2 apply identically.**

> **Note:** The chart does not template `HTTPRoute` in v0.6 because
> controller coverage for weighted `backendRefs` across controllers was still
> uneven. Promotion to a first-class chart template is filed as
> `V0.6-OPS-1-followup-gateway-api` for v0.7.

---

## 11. Optional: Argo Rollouts / Flagger

For automated metric-driven canary promotion (e.g. auto-promote when error
rate < 1 % for 5 minutes, auto-rollback otherwise), use Flagger or Argo
Rollouts.

These tools consume the same Traefik IngressRoute/TraefikService primitives
described in §4 and drive the weight progression via their own controllers.
They are not the default because they require installing a controller
dependency that many operators do not have.

**Quick recipe with Flagger:**

```yaml
# canary.flagger.yaml (not a chart template — operator-owned)
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: gw
  namespace: s3-gateway
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: gw-canary-s3-encryption-gateway
  ingressRef:
    apiVersion: traefik.io/v1alpha1
    kind: IngressRoute
    name: gateway
  analysis:
    interval: 1m
    threshold: 5
    maxWeight: 100
    stepWeight: 10
    metrics:
      - name: request-success-rate
        thresholdRange:
          min: 99
        interval: 1m
      - name: request-duration
        thresholdRange:
          max: 500   # ms p99
        interval: 1m
```

Documentation: https://docs.flagger.app/tutorials/traefik-progressive-delivery

---

## 12. Migration Note for ingress-nginx Operators

The chart's standard `ingress.enabled` path continues to work — Traefik,
Contour, HAProxy Ingress, and Emissary all consume `networking.k8s.io/v1`
Ingress resources. You do not need to change anything for single-release
deployments.

For canary deployments, `nginx.ingress.kubernetes.io/canary-*` annotations
are **not generated** by this chart. They only work with ingress-nginx and
ingress-nginx is in maintenance-mode upstream. The recommended migration is:

1. Stay on `ingress.enabled` for normal single-release deployments (no change).
2. For canary, use either:
   - **Traefik**: migrate to `ingress.traefik.enabled` and use the
     `TraefikService` weighted recipe in §4.
   - **Gateway API** (controller-portable): use the `HTTPRoute` recipe in §10.

---

## 14. Choosing a Values Overlay (V0.6-OPS-2)

The chart ships four values overlay files. Compose them with `helm install -f` in
the order shown — later overlays take precedence over earlier ones.

| Overlay | When to use | Enables | Disables |
|---------|-------------|---------|----------|
| `values.yaml` | Always — base defaults | Single-replica, info log, TLS off | HPA, PDB, NetworkPolicy, ServiceMonitor |
| `values.prod.yaml` | Production clusters | 3-replica HA floor, HPA (3–20), PDB (minAvailable: 2), NetworkPolicy, ServiceMonitor, TLS via cert-manager, audit, rate-limit, preStop hook | — |
| `values.dev.yaml` | Local kind/minikube | Debug log, audit logging, in-cluster Valkey subchart | HPA, PDB, NetworkPolicy, ServiceMonitor |
| `values.fips.yaml` | FIPS 140-3 regulated environments | FIPS image tag (`latest-fips`), `GOFIPS140=v1.0.0` env var, compliance pod annotations | — |

**Composition order examples:**

```bash
# Production (most common):
helm install s3gw . \
  -f values.yaml \
  -f values.prod.yaml \
  -f my-cluster-secrets.yaml    # backend creds, encryption password

# Production + FIPS:
helm install s3gw . \
  -f values.yaml \
  -f values.prod.yaml \
  -f values.fips.yaml \
  -f my-cluster-secrets.yaml

# Local development:
helm install s3gw . \
  -f values.yaml \
  -f values.dev.yaml \
  --set config.backend.endpoint.value=http://minio.local:9000 \
  --set config.backend.accessKey.value=minioadmin \
  --set config.backend.secretKey.value=minioadmin \
  --set config.encryption.password.value=dev-only-insecure

# Blue/green production:
helm install gw-blue . \
  -f values.yaml \
  -f values.prod.yaml \
  -f examples/values-blue.yaml \
  -f my-cluster-secrets.yaml
```

**Values not set by any overlay (operator-supplied):**

- `config.backend.accessKey` / `secretKey` / `endpoint`
- `config.encryption.password` (or `keyManager.*` for KMS)
- `ingress.*` host and TLS secret
- `certManager.issuer.*`

All four overlays are validated by `values.schema.json` on every `helm lint`
run. See §§ "Values Validation" in `helm/s3-encryption-gateway/README.md`
and the full plan at `docs/plans/V0.6-OPS-2-plan.md`.

---

## 13. References

1. Bilgin Ibryam & Roland Huss, *Kubernetes Patterns, 2nd Edition* (O'Reilly, 2023),
   Ch. 3 "Declarative Deployment" — authoritative taxonomy of release strategies.
2. Marko Luksa, *Kubernetes in Action, 2nd Edition* (Manning, 2026),
   Ch. 11 "Services", Ch. 16 "Deployment Strategies" — blue/green selector-flip.
3. Brendan Burns et al., *Kubernetes Best Practices, 2nd Edition* (O'Reilly, 2023),
   Ch. 4 "Services and Ingress" — terminationGracePeriodSeconds + preStop sizing.
4. Betsy Beyer et al., *The Site Reliability Workbook* (O'Reilly, 2018),
   Ch. 16 "Canarying Releases" — SRE-canonical canary procedure.
5. Jez Humble & David Farley, *Continuous Delivery* (Addison-Wesley, 2010),
   Ch. 10 — original blue/green and canary articulation.
6. Rahul Sharma & Akshay Mathur, *Traefik API Gateway for Microservices* (Apress, 2020),
   Ch. 6-7 — IngressRoute, TraefikService kind Weighted, sticky sessions.
7. Heather Adkins et al., *Building Secure and Reliable Systems* (O'Reilly, 2020),
   Ch. 18-19 — fail-closed defaults, rollback-first posture.
8. ADR 0007 — Admin API & Key Rotation (`docs/adr/0007-admin-api-key-rotation.md`)
9. ADR 0009 — Encrypted Multipart Uploads (`docs/adr/0009-encrypted-multipart-uploads.md`)
10. Traefik Proxy docs — IngressRoute / TraefikService:
    https://doc.traefik.io/traefik/providers/kubernetes-crd/
11. Kubernetes Gateway API — HTTPRoute:
    https://gateway-api.sigs.k8s.io/api-types/httproute/

