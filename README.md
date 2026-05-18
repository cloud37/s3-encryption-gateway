# S3 Encryption Gateway Helm Chart

A Helm chart for deploying the S3 Encryption Gateway - a transparent proxy that provides client-side encryption for S3-compatible storage services.

## Description

The S3 Encryption Gateway sits between S3 clients and backend storage providers, encrypting/decrypting data transparently while maintaining full S3 API compatibility. This Helm chart simplifies deployment to Kubernetes clusters.

## Repository

This chart is available at: **https://kenchrcum.github.io/s3-encryption-gateway**

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- A backend S3-compatible storage service (AWS S3, MinIO, Wasabi, Hetzner, etc.)
- Secrets containing backend credentials and encryption password

## Installation

### Add the Helm repository

```bash
helm repo add s3-encryption-gateway https://kenchrcum.github.io/s3-encryption-gateway
helm repo update
```

### Install the chart

```bash
helm install my-gateway s3-encryption-gateway/s3-encryption-gateway \
  --set config.backend.accessKey.valueFrom.secretKeyRef.name=my-secrets \
  --set config.backend.accessKey.valueFrom.secretKeyRef.key=access-key \
  --set config.backend.secretKey.valueFrom.secretKeyRef.name=my-secrets \
  --set config.backend.secretKey.valueFrom.secretKeyRef.key=secret-key \
  --set config.encryption.password.valueFrom.secretKeyRef.name=my-secrets \
  --set config.encryption.password.valueFrom.secretKeyRef.key=encryption-password
```

## Configuration

All configuration options support two methods:

1. **Direct values**: Set a value directly in `values.yaml` or via `--set`
2. **valueFrom**: Reference values from existing Secrets or ConfigMaps

### Using valueFrom with Secrets

Most sensitive values should be stored in Kubernetes Secrets and referenced:

```yaml
config:
  backend:
    accessKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-access-key
    secretKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-secret-key
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

### Using valueFrom with ConfigMaps

Non-sensitive configuration can be stored in ConfigMaps:

```yaml
config:
  backend:
    endpoint:
      valueFrom:
        configMapKeyRef:
          name: s3-encryption-gateway-config
          key: backend-endpoint
    region:
      valueFrom:
        configMapKeyRef:
          name: s3-encryption-gateway-config
          key: backend-region
```

### Configuration Options

#### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `track` | Blue/green or canary track label (`""`, `"blue"`, `"green"`, `"stable"`, `"canary"`). Empty = no label (backward-compatible). When set, a shared external Valkey address is required and `valkey.enabled` must be `false`. | `""` |
| `config.listenAddr` | Listen address | `":8080"` |
| `config.logLevel` | Log level (`debug`, `info`, `warn`, `error`) | `"info"` |
| `config.proxiedBucket` | Single bucket proxy mode — restricts gateway to one backend bucket (optional) | `""` |
| `config.policies` | Glob path to per-bucket policy YAML files mounted in the container (optional) | `""` |

#### Backend Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.backend.endpoint` | S3 backend endpoint URL | `"https://s3.amazonaws.com"` |
| `config.backend.region` | S3 backend region | `"us-east-1"` |
| `config.backend.accessKey` | Backend access key (use valueFrom) | `""` |
| `config.backend.secretKey` | Backend secret key (use valueFrom) | `""` |
| `config.backend.provider` | Provider hint string (optional) | `""` |
| `config.backend.useSSL` | Use SSL for backend connection | `"true"` |
| `config.backend.usePathStyle` | Use path-style bucket addressing | `"false"` |
| `config.backend.useClientCredentials` | Forward client-supplied credentials to the backend | `"false"` |

**Note on `useClientCredentials`**: When set to `"true"`, the gateway extracts credentials from client requests instead of using configured backend credentials. In this mode:
- `config.backend.accessKey` and `config.backend.secretKey` are **NOT required** and will be excluded from the deployment
- Clients must provide credentials via **query parameters only** (`?AWSAccessKeyId=...&AWSSecretAccessKey=...`)
- **AWS Signature V4 (Authorization header) is NOT supported** — the signature includes the Host header, which prevents forwarding requests to the backend
- Requests without valid credentials will fail with `AccessDenied`
- Useful for providers like Hetzner that don't support per-bucket access keys

#### Encryption Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.encryption.password` | Master encryption password (use valueFrom for production) | `""` |
| `config.encryption.keyFile` | Path to an encryption key file (optional) | `""` |
| `config.encryption.preferredAlgorithm` | Preferred AEAD algorithm (`AES256-GCM`, `ChaCha20-Poly1305`) | `"AES256-GCM"` |
| `config.encryption.supportedAlgorithms` | Comma-separated list of algorithms accepted for decryption | `"AES256-GCM,ChaCha20-Poly1305"` |
| `config.encryption.keyManager.enabled` | Enable external KMS / key-manager mode | `"false"` |
| `config.encryption.keyManager.provider` | KMS provider: `cosmian` (supported), `aws`, `vault` (planned) | `"cosmian"` |
| `config.encryption.keyManager.dualReadWindow` | Number of previous key versions tried during rotation | `"1"` |
| `config.encryption.keyManager.cosmian.endpoint` | Cosmian KMIP endpoint (JSON/HTTP: `http://host:9998/kmip/2_1`; binary: `host:5696`) | `""` |
| `config.encryption.keyManager.cosmian.timeout` | KMS operation timeout | `"10s"` |
| `config.encryption.keyManager.cosmian.keys` | Comma-separated wrapping keys (`"key1:v1,key2:v2"`) | `""` |
| `config.encryption.keyManager.cosmian.caCert` | CA certificate for TLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.clientCert` | Client certificate for mTLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.clientKey` | Client private key for mTLS (use valueFrom) | `""` |
| `config.encryption.keyManager.cosmian.insecureSkipVerify` | Skip TLS verification (testing only) | `"false"` |

**Key Manager (KMS) Configuration**: When `config.encryption.keyManager.enabled` is set to `"true"`, the gateway uses external KMS for envelope encryption. Currently, only **Cosmian KMIP** is fully supported.

**Protocol Selection**:
- **JSON/HTTP (Recommended)**:
  - Full URL: `http://host:9998/kmip/2_1` (recommended for clarity)
  - Base URL: `http://host:9998` (path `/kmip/2_1` is automatically appended)
  - No client certificates required for HTTP; `caCert` recommended for HTTPS
- **Binary KMIP (Advanced)**: `host:5696` — requires `caCert`, `clientCert`, `clientKey` (mutual TLS); not fully tested in CI

See the [KMS Compatibility Guide](../../docs/KMS_COMPATIBILITY.md) for details.

**Example KMS Configuration**:

```yaml
config:
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
    keyManager:
      enabled:
        value: "true"
      provider:
        value: "cosmian"
      dualReadWindow:
        value: "1"
      cosmian:
        endpoint:
          value: "http://cosmian-kms:9998/kmip/2_1"
        timeout:
          value: "10s"
        keys:
          value: "wrapping-key-1:1"
        caCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: ca-cert
        clientCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-cert
        clientKey:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-key
        insecureSkipVerify:
          value: "false"
```

#### Encrypted Multipart Upload State (Valkey)

Encrypted multipart uploads (enabled per-bucket via policy files) require a Valkey instance for in-flight state storage. Use the built-in Valkey subchart for development or point at an external cluster for production.

**Valkey subchart (development / single-release deployments)**:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `valkey.enabled` | Deploy the Valkey subchart in-cluster. Set to `false` when using an external Valkey or in blue/green topologies. | `false` |
| `valkey.architecture` | Valkey architecture (`standalone`, `replication`) | `standalone` |
| `valkey.auth.enabled` | Enable Valkey authentication | `false` |

> **Blue/green and canary deployments**: `valkey.enabled` **must** be `false`. Both tracks must share a single external Valkey cluster. Set the address via `config.multipartState.valkey.addr`.

**External Valkey connection (`config.multipartState.valkey.*`)**:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.multipartState.valkey.addr` | External Valkey address (`host:port`). Auto-wired when `valkey.enabled: true`. | `""` |
| `config.multipartState.valkey.tls.enabled` | Enable TLS for Valkey connection | `""` |
| `config.multipartState.valkey.tls.caFile` | CA certificate file for Valkey TLS | `""` |
| `config.multipartState.valkey.tls.certFile` | Client certificate file for Valkey mTLS | `""` |
| `config.multipartState.valkey.tls.keyFile` | Client key file for Valkey mTLS | `""` |
| `config.multipartState.valkey.insecureAllowPlaintext` | Allow plaintext Valkey (development only) | `""` |
| `config.multipartState.valkey.ttlSeconds` | TTL for in-flight MPU state records in Valkey (default: `604800` = 7 days) | `""` |

#### Compression Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.compression.enabled` | Enable transparent compression before encryption | `"false"` |
| `config.compression.minSize` | Minimum object size to compress (bytes) | `"1024"` |
| `config.compression.contentTypes` | Comma-separated content types to compress | `"text/plain,application/json,application/xml"` |
| `config.compression.algorithm` | Compression algorithm | `"gzip"` |
| `config.compression.level` | Compression level (1–9) | `"6"` |

#### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.readTimeout` | HTTP read timeout (0 = disabled; use readHeaderTimeout for slow-loris protection) | `"0s"` |
| `config.server.writeTimeout` | HTTP write timeout (0 = disabled; required for large object streaming) | `"0s"` |
| `config.server.idleTimeout` | HTTP idle connection timeout | `"60s"` |
| `config.server.readHeaderTimeout` | HTTP read header timeout | `"10s"` |
| `config.server.maxHeaderBytes` | Maximum request header size (bytes) | `"1048576"` |

#### TLS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.tls.enabled` | Enable TLS on the gateway listener | `"false"` |
| `config.tls.useCertManager` | Provision certificates automatically via cert-manager | `"false"` |
| `config.tls.certFile` | TLS certificate file path (when not using cert-manager) | `""` |
| `config.tls.keyFile` | TLS private key file path (when not using cert-manager) | `""` |

**Note**: When `config.tls.enabled` is `"true"` and `config.tls.useCertManager` is `"false"`, you must provide `certFile` and `keyFile` (validated by the values schema). When TLS is enabled the Service automatically uses port `443` with port name `https`.

#### cert-manager Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certManager.issuer.name` | Issuer resource name (defaults to chart fullname) | `""` |
| `certManager.issuer.namespace` | Issuer namespace (defaults to release namespace) | `""` |
| `certManager.issuer.selfSigned` | Self-signed issuer spec (set to `{}` to use self-signed) | `{}` |
| `certManager.issuer.clusterIssuer` | Name of a pre-existing ClusterIssuer (alternative to selfSigned) | `""` |
| `certManager.certificate.extraDNSNames` | Additional DNS SANs for the certificate | `[]` |
| `certManager.certificate.duration` | Certificate validity period | `"2160h"` |
| `certManager.certificate.renewBefore` | Renew this long before expiry | `"720h"` |

**cert-manager Integration**: When `config.tls.useCertManager` is enabled, the chart automatically creates `Issuer` and `Certificate` resources. The TLS certificate and key are automatically mounted into the pod.

#### Rate Limiting

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.rateLimit.enabled` | Enable per-connection rate limiting | `"false"` |
| `config.rateLimit.limit` | Maximum requests per window | `"100"` |
| `config.rateLimit.window` | Rate limit time window | `"60s"` |

#### Cache Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.cache.enabled` | Enable response caching | `"false"` |
| `config.cache.maxSize` | Maximum cache size (bytes) | `"104857600"` |
| `config.cache.maxItems` | Maximum number of cached items | `"1000"` |
| `config.cache.defaultTTL` | Default cache entry TTL | `"5m"` |

#### Audit Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.audit.enabled` | Enable audit logging | `"false"` |
| `config.audit.maxEvents` | Maximum in-memory audit events | `"10000"` |
| `config.audit.redactMetadataKeys` | Comma-separated metadata key names to redact from audit log | `""` |
| `config.audit.sink.type` | Sink type (`stdout`, `file`, `http`) | `"stdout"` |
| `config.audit.sink.endpoint` | HTTP sink endpoint URL (for `type=http`) | `""` |
| `config.audit.sink.filePath` | Log file path (for `type=file`) | `""` |
| `config.audit.sink.batchSize` | Maximum events per write batch | `"100"` |
| `config.audit.sink.flushInterval` | Maximum time between flushes | `"5s"` |
| `config.audit.sink.retryCount` | Retries on failed writes | `"3"` |
| `config.audit.sink.retryBackoff` | Initial retry backoff duration | `"1s"` |

#### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Create a standard `networking.k8s.io/v1` Ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Additional ingress annotations | `{}` |
| `ingress.hosts` | List of ingress hosts and paths | `[]` |
| `ingress.tls` | TLS configuration for the Ingress | `[]` |

**Traefik CRD Ingress** (mutually exclusive with `ingress.enabled`):

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.traefik.enabled` | Render a Traefik `IngressRoute` CRD (requires Traefik ≥ v3.0) | `false` |
| `ingress.traefik.entryPoints` | Traefik entrypoint names | `["websecure"]` |
| `ingress.traefik.host` | `Host()` matcher — the S3 hostname clients will use | `""` |
| `ingress.traefik.tls` | TLS stanza (`secretName`, `certResolver`) | `{}` |
| `ingress.traefik.middlewares` | List of Traefik Middleware references (`name`, `namespace`) | `[]` |
| `ingress.traefik.weighted.enabled` | Render a `kind: Weighted` TraefikService for canary traffic splitting | `false` |
| `ingress.traefik.weighted.services` | List of backend services with weights summing to 100 (`name`, `port`, `weight`) | `[]` |
| `ingress.traefik.weighted.sticky` | Sticky session cookie config (`cookie.name`, `httpOnly`, `secure`, `sameSite`) | `{}` |

**Common Ingress Annotations**:
- `kubernetes.io/ingress.class: nginx`
- `cert-manager.io/cluster-issuer: letsencrypt-prod`
- `nginx.ingress.kubernetes.io/ssl-redirect: "true"`
- `nginx.ingress.kubernetes.io/proxy-body-size: "0"`
- `nginx.ingress.kubernetes.io/proxy-read-timeout: "600"`

#### Deployment Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `kenchrcum/s3-encryption-gateway` |
| `image.tag` | Container image tag | `"0.8.0"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override the chart name portion of resource names | `""` |
| `fullnameOverride` | Override the full resource name | `""` |
| `podAnnotations` | Extra annotations added to every pod | `{}` |
| `podSecurityContext` | Pod-level security context (`runAsNonRoot`, `runAsUser`, `fsGroup`) | See values.yaml |
| `securityContext` | Container-level security context (`readOnlyRootFilesystem`, `allowPrivilegeEscalation`, `seccompProfile`, etc.) | See values.yaml |
| `terminationGracePeriodSeconds` | Pod termination grace period. Increase for blue/green drain (≥ p99 request duration + 10 s). | `30` |
| `lifecycle` | Container lifecycle hooks. Use a `preStop` sleep equal to the kube-proxy propagation tail for zero-downtime traffic flips. | `{}` |
| `resources` | CPU/memory resource requests and limits | See values.yaml |
| `nodeSelector` | Node selector labels | `{}` |
| `tolerations` | Pod tolerations | `[]` |
| `affinity` | Pod affinity/anti-affinity rules | `{}` |
| `topologySpreadConstraints` | Pod topology spread constraints | `[]` |

#### Health Probes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe.httpGet.path` | Liveness probe path | `/live` |
| `livenessProbe.initialDelaySeconds` | Seconds before first liveness check | `10` |
| `livenessProbe.periodSeconds` | Liveness probe period | `30` |
| `livenessProbe.timeoutSeconds` | Liveness probe timeout | `3` |
| `livenessProbe.failureThreshold` | Failures before pod is restarted | `3` |
| `readinessProbe.httpGet.path` | Readiness probe path | `/ready` |
| `readinessProbe.initialDelaySeconds` | Seconds before first readiness check | `5` |
| `readinessProbe.periodSeconds` | Readiness probe period | `10` |
| `readinessProbe.timeoutSeconds` | Readiness probe timeout | `3` |
| `readinessProbe.failureThreshold` | Failures before pod is removed from endpoints | `3` |

The `/ready` endpoint performs dependency health checks (KMS, Valkey) and returns `503` with a JSON `checks` map if any configured dependency is unhealthy. The aliases `/readyz`, `/healthz`, and `/livez` follow Kubernetes conventions.

#### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a `ServiceAccount` for the gateway | `true` |
| `serviceAccount.annotations` | Annotations to add to the ServiceAccount (e.g. IRSA / Workload Identity) | `{}` |
| `serviceAccount.name` | Override the generated ServiceAccount name | `""` |

#### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.enabled` | Create a Kubernetes `Service` | `true` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port (overridden to `443` when TLS is enabled) | `80` |
| `service.targetPort` | Container target port | `8080` |

**Note**: When `service.enabled` is `false`, `ServiceMonitor` is also disabled automatically. Keep the Service enabled for stable DNS-based service discovery.

#### Autoscaling (HPA)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable Horizontal Pod Autoscaler | `false` |
| `autoscaling.minReplicas` | Minimum number of replicas | `2` |
| `autoscaling.maxReplicas` | Maximum number of replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU utilization target (%) | `70` |
| `autoscaling.targetMemoryUtilizationPercentage` | Memory utilization target (%) | `80` |
| `autoscaling.behavior.scaleDown.stabilizationWindowSeconds` | Scale-down stabilisation window | `300` |
| `autoscaling.behavior.scaleUp.stabilizationWindowSeconds` | Scale-up stabilisation window | `0` |

#### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Create a `PodDisruptionBudget` | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods during disruption (integer or percentage) | `""` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods during disruption (integer or percentage) | `""` |

#### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Create a Prometheus Operator `ServiceMonitor` | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.labels` | Extra labels for ServiceMonitor (e.g. `prometheus: kube-prometheus`) | `{}` |
| `podMonitor.enabled` | Create a Prometheus Operator `PodMonitor` (alternative to ServiceMonitor) | `false` |
| `podMonitor.interval` | Scrape interval | `30s` |
| `podMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `podMonitor.labels` | Extra labels for PodMonitor | `{}` |

**ServiceMonitor vs PodMonitor**: `ServiceMonitor` targets the Service (recommended). `PodMonitor` targets pods directly — useful when the Service is disabled or for fine-grained pod-level metrics. Both emit a `track` relabel rule when `track` is set, enabling per-track PromQL queries in blue/green topologies.

#### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Create a `NetworkPolicy` | `false` |
| `networkPolicy.policyTypes` | Policy types to enforce | `[Ingress, Egress]` |
| `networkPolicy.namespaceIsolation` | Restrict ingress to pods in the same namespace only | `true` |
| `networkPolicy.namespaceLabel.key` | Namespace label key used for isolation matching | `"kubernetes.io/metadata.name"` |
| `networkPolicy.egress.awsS3` | Allow egress to AWS S3 (adjust CIDRs per region) | `false` |
| `networkPolicy.egress.minioInternal` | Allow egress to an in-cluster MinIO service | `false` |
| `networkPolicy.egress.monitoring` | Allow egress to monitoring/logging services | `false` |
| `networkPolicy.ingress.ingressControllers` | Allow ingress from ingress controller pods | `false` |
| `networkPolicy.ingress.ingressNamespace` | Namespace of the ingress controller | `"ingress-nginx"` |
| `networkPolicy.ingress.monitoring` | Allow ingress from Prometheus scrape pods | `false` |
| `networkPolicy.ingress.monitoringNamespace` | Namespace of the Prometheus stack | `"monitoring"` |

**Namespace Isolation**: When `namespaceIsolation` is enabled (default), only pods in the same namespace can access the gateway. Most Kubernetes distributions auto-label namespaces with `kubernetes.io/metadata.name`. If yours does not, either label it or set a custom `namespaceLabel.key`.

## Extending the Chart

The Helm chart supports several extension points to customize the deployment for advanced use cases.

### Extra Environment Variables

Add custom environment variables to the main container:

```yaml
extraEnv:
  - name: MY_CUSTOM_VAR
    value: "my-value"
  - name: MY_SECRET_VAR
    valueFrom:
      secretKeyRef:
        name: my-secret
        key: my-key
```

### Extra Volumes and Volume Mounts

Mount additional volumes into the main container:

```yaml
extraVolumes:
  - name: my-config
    configMap:
      name: my-configmap
  - name: my-secret-volume
    secret:
      secretName: my-secret

extraVolumeMounts:
  - name: my-config
    mountPath: /etc/my-config
    readOnly: true
  - name: my-secret-volume
    mountPath: /etc/my-secrets
    readOnly: true
```

### Init Containers

Run initialization containers before the main gateway starts:

```yaml
initContainers:
  - name: init-myservice
    image: busybox:1.35
    command: ['sh', '-c', 'echo "Initializing..." && sleep 5']
    volumeMounts:
      - name: shared-data
        mountPath: /data
```

### Sidecar Containers

Run sidecar containers alongside the main gateway:

```yaml
sidecars:
  - name: sidecar-logger
    image: fluent/fluent-bit:2.0
    ports:
      - containerPort: 2020
    volumeMounts:
      - name: varlogcontainers
        mountPath: /var/log/containers
        readOnly: true
```

## Examples

### Basic Installation with Secrets

```bash
# Create secrets first
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key='YOUR_ACCESS_KEY' \
  --from-literal=backend-secret-key='YOUR_SECRET_KEY' \
  --from-literal=encryption-password='YOUR_ENCRYPTION_PASSWORD'

# Install with secrets
helm install my-gateway s3-encryption-gateway/s3-encryption-gateway \
  --namespace default
```

### KMS Mode with Cosmian KMIP

Deploy the gateway with external KMS (Cosmian KMIP) for envelope encryption and key rotation:

```bash
kubectl create secret generic s3-encryption-gateway-secrets \
  --from-literal=backend-access-key='YOUR_ACCESS_KEY' \
  --from-literal=backend-secret-key='YOUR_SECRET_KEY' \
  --from-literal=encryption-password='fallback-password-123456'

# If using TLS, also create certificate secrets
kubectl create secret generic cosmian-kms-certs \
  --from-file=ca-cert=/path/to/ca.pem \
  --from-file=client-cert=/path/to/client.crt \
  --from-file=client-key=/path/to/client.key
```

```yaml
config:
  backend:
    endpoint:
      value: "https://s3.amazonaws.com"
    region:
      value: "us-east-1"
    accessKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-access-key
    secretKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-secret-key
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
    keyManager:
      enabled:
        value: "true"
      provider:
        value: "cosmian"
      dualReadWindow:
        value: "1"
      cosmian:
        endpoint:
          # JSON/HTTP (recommended): full URL or base URL with auto-appended /kmip/2_1
          value: "http://cosmian-kms:9998/kmip/2_1"
        timeout:
          value: "10s"
        keys:
          value: "wrapping-key-1:1"
        caCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: ca-cert
        clientCert:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-cert
        clientKey:
          valueFrom:
            secretKeyRef:
              name: cosmian-kms-certs
              key: client-key
        insecureSkipVerify:
          value: "false"
```

**Notes:**
- `encryption.password` is still required as a fallback for objects encrypted before KMS was enabled
- `keys` format: `"key1:version1,key2:version2"` (comma-separated for rotation)
- Health checks automatically verify KMS connectivity via `/ready`

### Encrypted Multipart Uploads with Valkey

Define bucket policies inline in `values.yaml` using the top-level `policies`
list. The chart renders a ConfigMap, mounts it, and sets `POLICIES`
automatically — no manual `extraVolumes` / `extraVolumeMounts` required.

#### Development / staging (in-cluster Valkey subchart)

```yaml
valkey:
  enabled: true                  # auto-wires VALKEY_ADDR → <release>-valkey:6379
  architecture: standalone
  auth:
    enabled: false               # enable + use existingSecret in production

policies:
  - id: encrypted-uploads
    buckets:
      - "my-important-bucket"
      - "logs-*"
    encrypt_multipart_uploads: true
    require_encryption: true
  - id: public-assets
    buckets:
      - "public-*"
    require_encryption: false
```

Each entry maps 1:1 to `PolicyConfig` (`internal/config/policy.go`). All
fields are supported: `encrypt_multipart_uploads`, `require_encryption`,
`disallow_lock_bypass`, and per-bucket `encryption` / `compression` /
`rate_limit` overrides.

#### Production (external Valkey, TLS)

Disable the subchart and point at your shared Valkey cluster. The `policies`
list works identically:

```yaml
valkey:
  enabled: false

config:
  multipartState:
    valkey:
      addr:
        value: "valkey-shared.mpu-state.svc.cluster.local:6379"
      tls:
        enabled:
          value: "true"
        caFile:
          value: "/etc/valkey-tls/ca.crt"
      insecureAllowPlaintext:
        value: "false"

policies:
  - id: encrypted-uploads
    buckets:
      - "my-important-bucket"
    encrypt_multipart_uploads: true
    require_encryption: true
```

> **Note:** `policies` (top-level list) and `config.policies.value` /
> `config.policies.valueFrom` are mutually exclusive. Using both causes a
> render-time error (Guard 6). Use `config.policies` only when you need to
> reference policy files that are mounted from an external source outside the
> chart (e.g. from a corporate Secret store).

### Single Bucket Proxy Mode

Restrict the gateway to a single backend bucket, minimising IAM policy requirements:

```yaml
config:
  proxiedBucket:
    value: "my-secure-bucket"
  backend:
    endpoint:
      value: "https://s3.amazonaws.com"
    region:
      value: "us-east-1"
    accessKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-access-key
    secretKey:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: backend-secret-key
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

### Client Credentials Mode

Forward client-provided credentials to the backend (e.g. for Hetzner):

```yaml
config:
  proxiedBucket:
    value: "my-bucket"
  backend:
    endpoint:
      value: "https://your-bucket.your-region.your-objectstorage.com"
    region:
      value: "nbg1"
    useClientCredentials:
      value: "true"
    # accessKey and secretKey are NOT required when useClientCredentials is true
  encryption:
    password:
      valueFrom:
        secretKeyRef:
          name: s3-encryption-gateway-secrets
          key: encryption-password
```

Clients must include credentials via **query parameters only**: `?AWSAccessKeyId=...&AWSSecretAccessKey=...`.
AWS Signature V4 (`Authorization` header) is **not supported** in this mode.

### With Pod Lifecycle Hooks (Progressive Delivery)

For blue/green and canary deployments, configure a preStop hook to drain in-flight connections before the pod receives a SIGTERM:

```yaml
terminationGracePeriodSeconds: 60
lifecycle:
  preStop:
    exec:
      command: ["sh", "-c", "sleep 10"]
```

### Custom Configuration with ConfigMap

```yaml
config:
  backend:
    endpoint:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: backend-endpoint
    region:
      valueFrom:
        configMapKeyRef:
          name: s3-gateway-config
          key: backend-region
  rateLimit:
    enabled:
      value: "true"
    limit:
      value: "200"
    window:
      value: "60s"
```

### With Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
```

### With Prometheus Monitoring

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels:
    prometheus: kube-prometheus
```

### With Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: s3-gateway.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: s3-gateway-tls
      hosts:
        - s3-gateway.example.com
```

### With Traefik IngressRoute

```yaml
ingress:
  traefik:
    enabled: true
    entryPoints: ["websecure"]
    host: "s3-gateway.example.com"
    tls:
      certResolver: "letsencrypt"
    middlewares:
      - name: my-auth-middleware
        namespace: default
```

### With Pod Disruption Budget

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
  # Alternative: maxUnavailable: "50%"
```

### With Topology Spread Constraints

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: s3-encryption-gateway
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: s3-encryption-gateway
```

### With cert-manager TLS

```yaml
config:
  tls:
    enabled:
      value: "true"
    useCertManager:
      value: "true"

certManager:
  issuer:
    name: s3-gateway-issuer
    selfSigned: {}
    # Or use Let's Encrypt:
    # clusterIssuer: letsencrypt-prod
  certificate:
    extraDNSNames:
      - s3-gateway.internal.example.com
    duration: "2160h"
    renewBefore: "720h"
```

### With Namespace Isolation

```yaml
service:
  enabled: true  # Keep enabled for stable DNS resolution

networkPolicy:
  enabled: true
  namespaceIsolation: true
  namespaceLabel:
    key: "kubernetes.io/metadata.name"
  egress:
    awsS3: false      # set true if backend is AWS S3
    minioInternal: true
  ingress:
    ingressControllers: true
    ingressNamespace: "ingress-nginx"
    monitoring: true
    monitoringNamespace: "monitoring"
```

### With IRSA / Workload Identity

Annotate the ServiceAccount for AWS IRSA or GKE Workload Identity:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/s3-gateway-role"
```

## Progressive Delivery

The chart ships production-safe blue/green and canary deployment recipes for
zero-downtime upgrades. See **[docs/OPS_DEPLOYMENT.md](../../docs/OPS_DEPLOYMENT.md)**
for the complete runbook.

### Key points

- **Zero breaking changes.** The `track` value defaults to `""` (no label).
  Existing single-release deployments are byte-for-byte unchanged.
- **Fail-closed guard-rails.** Setting `track` without a shared external Valkey
  address, or enabling both `ingress.enabled` and `ingress.traefik.enabled`,
  causes `helm template` to fail with a clear, actionable message.
- **Traefik v3 first-class support.** `ingress.traefik.enabled` and
  `ingress.traefik.weighted.enabled` render Traefik `IngressRoute` and
  `TraefikService` CRDs (requires Traefik ≥ v3.0).
- **Shared Valkey is mandatory for blue/green and canary.** Both tracks must
  point at the same external Valkey cluster. Set `valkey.enabled: false` and
  configure `config.multipartState.valkey.addr` on all releases.

### Quick start

```bash
# Blue side:
helm install gw-blue . \
  --values examples/values-blue.yaml \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379

# Green side (new version):
helm install gw-green . \
  --set image.tag=v0.8.0 \
  --values examples/values-green.yaml \
  --set config.multipartState.valkey.addr.value=valkey-shared.mpu-state.svc.cluster.local:6379

# Cutover:
docs/examples/bluegreen/cutover.sh green
# Rollback:
docs/examples/bluegreen/cutover.sh blue
```

## Values Validation

This chart ships a `values.schema.json` ([JSON Schema draft-07](http://json-schema.org/draft-07/schema)) that validates all values **client-side** before the chart reaches the cluster.

Helm enforces the schema during `helm lint`, `helm install`, `helm upgrade`, and `helm template`. Errors appear with JSON-path-prefixed messages like:

```
at '/replicaCount': got string, want integer
at '/config/logLevel/value': Must be one of: debug, info, warn, error
at '': 'not' failed  (both ingress.enabled and ingress.traefik.enabled are true)
```

**What the schema catches early (before template rendering):**

| Rule | Description |
|------|-------------|
| Type mismatches | `replicaCount: "2"` (string) is rejected; must be an integer |
| Enum violations | `logLevel: verbose` rejected; must be one of `debug/info/warn/error` |
| I1 — track + Valkey | Setting `track: blue` with `valkey.enabled: true` is rejected |
| I2 — ingress mutex | `ingress.enabled: true` + `ingress.traefik.enabled: true` is rejected |
| I3 — weighted requires Traefik | `weighted.enabled: true` without `traefik.enabled: true` is rejected |
| I5 — KeyManager provider | `keyManager.enabled=true` with an unknown provider is rejected |
| I7 — TLS cert required | `tls.enabled=true` + `useCertManager=false` without `certFile`/`keyFile` is rejected |

> The schema is intentionally permissive at the root (`additionalProperties: true`) so that overlays like `values.fips.yaml` can add arbitrary pod annotations and extraEnv entries without triggering false positives. Strict `additionalProperties: false` is applied only at well-structured sub-trees (`config.backend.*`, `config.encryption.*`, `ingress.traefik.weighted.*`).

If `helm lint` fails with a JSON-path error, consult the description in
`values.schema.json` at that path — the description contains the fix.
To bypass schema validation in an emergency (template guards still fire):
```bash
helm install ... --disable-openapi-validation
```

### Schema source

- `helm/s3-encryption-gateway/values.schema.json` — hand-written, ~1 400 lines with `$defs` reuse
- `helm/s3-encryption-gateway/tests/schema/` — positive and negative test cases
- `helm/s3-encryption-gateway/tests/schema/run-negative.sh` — local harness
- `.github/workflows/helm-test.yml` jobs: `lint-overlays`, `schema-negative`, `schema-drift`, `render-overlays`

See `docs/plans/V0.6-OPS-2-plan.md` for the full design document.

## Upgrading

```bash
helm repo update
helm upgrade my-gateway s3-encryption-gateway/s3-encryption-gateway
```

## Uninstalling

```bash
helm uninstall my-gateway
```

## Security Best Practices

1. **Use Secrets for Sensitive Data**: Always use `valueFrom.secretKeyRef` for:
   - Backend access keys and secret keys
   - Encryption passwords
   - KMS credentials and TLS certificates

2. **RBAC**: The chart creates a ServiceAccount. Annotate it for IRSA / Workload Identity where applicable.

3. **Network Policies**: Enable network policies for additional security:
   ```yaml
   networkPolicy:
     enabled: true
     namespaceIsolation: true
   ```
   When `namespaceIsolation` is enabled, only pods in the same namespace can access the gateway.

4. **Single Bucket Proxy**: Use `proxiedBucket` to restrict access to a single bucket, minimising IAM policy requirements.

5. **TLS**: Enable TLS on the gateway listener (`config.tls.enabled`) and use cert-manager for automatic certificate rotation.

6. **FIPS**: Use `image.tag: 0.8.0-fips` and the `values.fips.yaml` overlay for FIPS-140-compliant deployments (AES-256-GCM only; ChaCha20-Poly1305 excluded).

## Troubleshooting

### Check Pod Logs

```bash
kubectl logs -l app.kubernetes.io/name=s3-encryption-gateway
```

### Check Pod Status

```bash
kubectl get pods -l app.kubernetes.io/name=s3-encryption-gateway
```

### Test Health Endpoints

```bash
# Via Service:
kubectl port-forward svc/s3-encryption-gateway 8080:80
curl http://localhost:8080/readyz

# Directly to pod (when Service is disabled):
kubectl port-forward <pod-name> 8080:8080
curl http://localhost:8080/readyz
```

The `/readyz` endpoint returns `200 OK` when all dependencies (KMS, Valkey) are healthy, or `503` with a JSON `checks` map identifying the failing dependency. Aliases: `/healthz`, `/livez`, `/ready`, `/live`.

## Support

For issues, feature requests, or questions:
- GitHub: https://github.com/kenchrcum/s3-encryption-gateway
- Chart Repository: https://kenchrcum.github.io/s3-encryption-gateway

## License

MIT License — see [LICENSE](https://github.com/kenchrcum/s3-encryption-gateway/blob/main/LICENSE) for details.
