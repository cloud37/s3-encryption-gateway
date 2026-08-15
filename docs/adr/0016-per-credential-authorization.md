# ADR 0016: Per-Credential Authorization

## Status

Accepted

## Context

Gateway credentials authenticate callers but backend credentials are shared. Backend IAM therefore cannot provide tenant authorization.

## Decision

Each gateway credential may declare exact bucket names or non-empty trailing-prefix patterns such as `tenant-*`. Omitted `buckets` remains unrestricted for compatibility; an explicit empty list denies every bucket. Object permissions are `ro` or `rw`, defaulting to `rw`. Bucket creation and deletion require explicit `create` and `delete` grants and are not implied by `rw`.

Authorization runs immediately after signature authentication and before backend-capable middleware or handlers. `PROXIED_BUCKET` intersects with, and never widens, a credential's policy. Copy operations require source-read and destination-write scope. ListBuckets filters the backend response and returns an empty inventory for a deny-all credential.

Credential reload builds and validates a full immutable snapshot before a single atomic publication. A failed reload retains the prior snapshot.

## Operation Matrix

| Operation | Required policy |
|---|---|
| Object GET, HEAD, list, and read subresources | `ro` or `rw`, bucket in scope |
| Object, multipart, and bucket-subresource mutations | `rw`, bucket in scope |
| CopyObject and UploadPartCopy | destination `rw`; source in scope and readable |
| CreateBucket | `bucket_permissions: [create]`, bucket in scope |
| DeleteBucket | `bucket_permissions: [delete]`, bucket in scope |
| ListBuckets | `ro` or `rw`; response filtered to effective scope |

Only exact bucket names and non-empty trailing-prefix patterns are accepted. `PROXIED_BUCKET` narrows every operation, including ListBuckets. Credential-file changes are watched and a replacement is published only after complete validation.

## Consequences

Operators can isolate tenants while continuing to use one backend identity. Policies remain bucket-level only; object-key policies and IAM policy evaluation are intentionally out of scope.
