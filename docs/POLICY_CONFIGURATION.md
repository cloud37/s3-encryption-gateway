# Policy Configuration

The S3 Encryption Gateway supports per-bucket or per-tenant configuration through policy files. This allows you to apply different encryption keys or rate limits depending on the bucket being accessed.

## Overview

Policies are defined in YAML files or indexed `GW_POLICY_N_*` environment
variables and loaded at startup and on configuration reload. When a request
comes in, the gateway checks the bucket name against the loaded policies. If a
match is found, the policy settings override the global configuration for that
request.

## Policy File Format

A policy file has the following structure:

```yaml
id: "tenant-a"                  # Unique identifier for the policy
buckets:                        # List of glob patterns to match bucket names
  - "tenant-a-*"
  - "shared-logs"

encryption:                     # (Optional) Override encryption settings
  password: "tenant-a-password"
  preferred_algorithm: "ChaCha20-Poly1305"
  key_manager:                  # (Optional) Override key manager settings
    enabled: true
    provider: "cosmian"
    # ... other key manager settings

disable_encryption: false       # Opt out of gateway encryption (e.g. restic)
require_encryption: false       # Mutually exclusive with disable_encryption
disallow_lock_bypass: true
encrypt_multipart_uploads: true # disable_encryption implies false

rate_limit:                     # (Optional) Override rate limit settings
  enabled: true
  limit: 50
  window: "60s"
```

## Configuration

To enable policies, you must specify where the gateway should look for policy files using the `policies` configuration in `config.yaml` or via environment variables.

### config.yaml

```yaml
policies:
  - "/etc/s3-gateway/policies/*.yaml"
  - "/mnt/policies/*.yml"
```

### Environment Variable

You can specify policy patterns via the `POLICIES` environment variable (comma-separated):

```bash
export POLICIES="/etc/s3-gateway/policies/*.yaml,/mnt/policies/*.yml"
```

## Precedence and Merging

File patterns are processed in configured order, with each glob's matches in
lexical order. Environment policies are appended in index order, stopping at
the first absent `GW_POLICY_N_ID`. For encryption selection, the **first
matching policy wins**; environment policies do not override an earlier
matching file policy. Reload preserves this ordering.

When a policy matches a bucket, it applies overrides to the base configuration using the following logic:

1.  **Encryption**:
    *   `password`: Overridden if specified in policy.
    *   `preferred_algorithm`: Overridden if specified in policy.
    *   `key_manager`: Overridden if `enabled` is true or `provider` is set in policy.
    *   Other fields (like `chunked_mode`, `chunk_size`) are preserved from the base configuration unless the implementation is updated to merge them.

2.  **Rate Limit**:
    *   The entire `rate_limit` section is replaced if specified in the policy.

## Atomic Reloads

Hot reload is enabled when a main configuration file exists or
`AUTH_CREDENTIALS_FILE` is configured. SIGHUP, a main-config file change, or a
credentials-file change reloads **both** policy sources, even if the policies
themselves did not change. Policy files are not independently watched; use
SIGHUP after changing them when hot reload is enabled. Process-environment and
Helm-rendered environment changes require a restart; SIGHUP cannot import
changes made outside the running process's environment.

The gateway prepares a complete candidate policy set separately from the live
manager, validates all files and environment entries, and publishes it under a
single short lock. Requests continue using the previous complete set during
loading. There is no intermediate empty or file-only set. Repeated reloads do
not accumulate policies; an intentionally empty candidate removes them.

If any source fails to load or validate, the complete previous set stays
active. Policy preparation happens before credentials or runtime gates are
changed, and the reload is reported as failed rather than successful. This is
atomic publication of the **policy set**, not a transaction spanning every
runtime subsystem or all policy lookups within an in-flight request.

For internal consumers, use `PolicyManager.ReloadPolicies` for a full live
reload, or `LoadPolicySnapshot` followed by `ReplaceSnapshot` when publication
must wait for other apply steps. Do not compose `Reset`, `LoadPolicies`, and
`LoadPoliciesFromEnv` against a live manager. Selected policy objects must be
treated as read-only.

### Bypass Buckets and GH-339

For applications that already encrypt their data, such as restic:

```bash
GW_POLICY_0_ID=restic-bypass
GW_POLICY_0_BUCKETS=backups
GW_POLICY_0_DISABLE_ENCRYPTION=true
```

Before the GH-339 fix (including release `0.12.1`), reload briefly removed
these policies. A PUT in that interval could return 200 while storing gateway
ciphertext; later GETs returned 409 `EncryptionConfigurationMismatch` and
listings exposed the larger stored size. A failed policy load could leave the
incorrect policy set active indefinitely.

On affected releases, avoid reloads while clients write or deploy without hot
reload and use coordinated restarts. Removing `AUTH_CREDENTIALS_FILE` alone is
not sufficient if a main configuration file still enables the watcher.

The fix prevents new miswrites; it does **not** convert existing affected
objects. Keep the mismatch refusal and follow the
[controlled recovery procedure](MIGRATION.md#recovering-gh-339-bypass-bucket-miswrites).

## Example Scenarios

### Scenario 1: Multi-Tenant Encryption

You have two tenants, "Acme" and "Globex", sharing the same gateway but requiring different encryption keys.

**Policy: Acme** (`acme-policy.yaml`)
```yaml
id: "acme"
buckets: ["acme-*"]
encryption:
  password: "acme-secret-key"
```

**Policy: Globex** (`globex-policy.yaml`)
```yaml
id: "globex"
buckets: ["globex-*"]
encryption:
  password: "globex-secret-key"
```

### Scenario 2: Archive Compression (Removed in v1.0)

Built-in compression was removed in V1.0-MAINT-2. For archive compression,
compose with s4 upstream:

```
client → s4 → s3-encryption-gateway → storage
```

## Kubernetes Deployment

In Kubernetes, you can store policies in a ConfigMap and mount them into the gateway pod.

1.  **Create ConfigMap**:
    ```bash
    kubectl create configmap gateway-policies --from-file=policies/
    ```

2.  **Configure Helm Chart**:
    In your `values.yaml`:
    ```yaml
    extraVolumes:
      - name: policies
        configMap:
          name: gateway-policies
    
    extraVolumeMounts:
      - name: policies
        mountPath: /etc/s3-gateway/policies
        readOnly: true
    
    config:
      policies:
        value: "/etc/s3-gateway/policies/*.yaml"
    ```
