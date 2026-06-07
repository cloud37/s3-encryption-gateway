# Policy Configuration

The S3 Encryption Gateway supports per-bucket or per-tenant configuration through policy files. This allows you to apply different encryption keys or rate limits depending on the bucket being accessed.

## Overview

Policies are defined in YAML files and loaded at startup. When a request comes in, the gateway checks the bucket name against the loaded policies. If a match is found, the policy settings override the global configuration for that request.

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

  # compression removed in v1.0 — compress upstream with s4
    - "application/json"

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

When a policy matches a bucket, it applies overrides to the base configuration using the following logic:

1.  **Encryption**:
    *   `password`: Overridden if specified in policy.
    *   `preferred_algorithm`: Overridden if specified in policy.
    *   `key_manager`: Overridden if `enabled` is true or `provider` is set in policy.
    *   Other fields (like `chunked_mode`, `chunk_size`) are preserved from the base configuration unless the implementation is updated to merge them.

2.  **Rate Limit**:
    *   The entire `rate_limit` section is replaced if specified in the policy.

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

