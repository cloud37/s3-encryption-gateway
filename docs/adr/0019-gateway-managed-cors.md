# ADR 0019: Gateway-managed bucket CORS

## Status

Accepted

## Context

Backend-native CORS does not cover responses constructed by the encryption
gateway and some backends do not implement bucket CORS APIs. Browser policy
must therefore be owned consistently at the gateway boundary while preserving
existing deployments by default.

## Decision

- `cors.mode` defaults to `passthrough`; `gateway` is an explicit opt-in and
  requires the shared Valkey client. Passthrough behavior remains unchanged.
- In gateway mode, bucket XML is validated and stored as the sole durable
  authority at `bucketcors:v1:<bucket>` with no expiration. Runtime `PUT` and
  `DELETE ?cors` changes are not reloaded from configuration files.
- Valkey persistence on retained storage, independently maintained backups,
  and a tested restore procedure are essential before enabling gateway mode.
  AOF/RDB configuration and readiness do not prove backup recoverability.
- The gateway evaluates bucket rules in order for preflight and actual
  responses. Missing policies may use an explicitly configured global fallback;
  corrupt records and store outages never activate fallback. Fallback is not
  returned by `GET ?cors`.
- Credentials are opt-in, apply to bucket and fallback matches, and require the
  response to echo a concrete validated Origin; wildcard Allow-Origin is never
  combined with credentials. ETag is not exposed unless explicitly configured.
- CORS configuration changes require coordinated restart; hot reload is
  rejected. Gateway-mediated bucket create/delete is required to prevent stale
  policy leaking when a bucket name is reused. Out-of-band lifecycle can race.

## Consequences

An empty but reachable Valkey can pass readiness while losing API-managed
policies: `GET ?cors` returns 404 and preflight denies unless configured
fallback applies (which may broaden browser visibility). Restore from backup or
re-apply the intended XML through authenticated `PUT ?cors`, then verify each
replica. Default passthrough does not add a durability requirement.
