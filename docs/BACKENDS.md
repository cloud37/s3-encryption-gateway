# Backend Storage Compatibility

The gateway supports multiple storage backends through a thin shim layer that
normalises each provider's S3-compatible API surface. The backend is selected
via `backend.type` in the configuration file (or the `BACKEND_TYPE` environment
variable).

Supported values: `"s3"` (default), `"gcs"`, `"azure"`.

---

## S3-compatible (AWS / MinIO / Hetzner / Wasabi / Backblaze / …)

The default backend. Routes all requests through the AWS SDK v2 S3 client.
Works with any S3-compatible object store.

| Feature | Supported? | Caveat |
|---|---|---|
| PutObject | ✅ | |
| GetObject | ✅ | |
| DeleteObject | ✅ | |
| HeadObject | ✅ | |
| ListObjects | ✅ | |
| Multipart Upload | ✅ | |
| CopyObject | ✅ | |
| UploadPartCopy | ✅ | |
| DeleteObjects | ✅ | |
| Object Tagging | ✅ | |
| Object Lock | ✅ | Requires bucket-level lock configuration |
| Presigned URLs | ✅ | |

**Configuration example:**

```yaml
backend:
  type: s3
  endpoint: "https://s3.amazonaws.com"
  region: us-east-1
  access_key: "${AWS_ACCESS_KEY_ID}"
  secret_key: "${AWS_SECRET_ACCESS_KEY}"
```

---

## Google Cloud Storage (GCS)

GCS exposes an [S3-compatible XML API](https://cloud.google.com/storage/docs/interoperability)
at `storage.googleapis.com`. Authentication uses HMAC keys (access key / secret
key), not service accounts.

| Feature | Supported? | Caveat |
|---|---|---|
| PutObject | ✅ | User-metadata keys are lowercased automatically |
| GetObject | ✅ | Returned metadata keys are lowercased |
| HeadObject | ✅ | Returned metadata keys are lowercased |
| DeleteObject | ✅ | |
| ListObjects | ✅ | |
| Multipart Upload | ⚠️ | **32-part limit.** At the default 5 MiB part size this caps objects at 160 MiB via multipart. Use larger parts (≤ 64 MiB) or single-part PUT for larger objects. |
| CopyObject | ✅ | `LastModified` may be missing in response; gateway substitutes `time.Now()` as fallback |
| UploadPartCopy | ✅ | Same 32-part limit applies |
| DeleteObjects | ✅ | |
| Object Tagging | ✅ | |
| Object Lock | ❌ | GCS XML API does not implement Object Lock |
| Presigned URLs | ✅ | |

**Additional notes:**

- Object metadata keys must be *lowercase*. The GCS shim automatically
  lowercases all keys on `PutObject` and normalises returned keys on
  `GetObject` / `HeadObject`.
- HMAC keys are created in the GCS console under *Cloud Storage → Settings →
  Interoperability*.
- Multipart uploads are limited to **32 parts**. Increase part size via the
  gateway's `server.max_part_buffer` setting to support larger objects.
- GCS does not support S3 Object Lock operations (`PutObjectRetention`,
  `GetObjectRetention`, `PutObjectLegalHold`, `GetObjectLegalHold`,
  `PutObjectLockConfiguration`, `GetObjectLockConfiguration`). These return
  HTTP 501 NotImplemented.

**Configuration example:**

```yaml
backend:
  type: gcs
  endpoint: "https://storage.googleapis.com"
  region: us-east-1
  access_key: "${GCS_HMAC_ACCESS_KEY}"
  secret_key: "${GCS_HMAC_SECRET_KEY}"
```

---

## Azure Blob Storage

Azure Blob Storage exposes an [S3-compatible API (preview)](
https://learn.microsoft.com/en-us/azure/storage/blobs/s3-api-overview).
The endpoint is typically `<account>.blob.core.windows.net`.

| Feature | Supported? | Caveat |
|---|---|---|
| PutObject | ✅ | Aggregate user-metadata size ≤ 8 KiB; key chars restricted |
| GetObject | ✅ | `BlobNotFound` mapped to S3 `NoSuchKey` |
| HeadObject | ✅ | `BlobNotFound` mapped to S3 `NoSuchKey` |
| DeleteObject | ✅ | |
| ListObjects | ✅ | |
| Multipart Upload | ✅ | |
| CopyObject | ✅ | |
| UploadPartCopy | ✅ | |
| DeleteObjects | ✅ | |
| Object Tagging | ✅ | |
| Object Lock | ❌ | All Object Lock operations return NotImplemented |
| Presigned URLs | ✅ | |

**Additional notes:**

- **Metadata size limit:** Azure enforces an 8 KiB aggregate limit on
  user-defined metadata (key names + values). The gateway's encryption
  metadata occupies ~600 bytes, leaving ~7.5 KiB for user metadata.
  Requests exceeding the limit are rejected with `InvalidArgument`.
- **Metadata key restrictions:** Azure metadata keys may only contain
  alphanumeric characters, underscores (`_`), dollar signs (`$`), and
  periods (`.`). The shim validates keys and rejects invalid ones with
  `InvalidArgument`.
- **Error mapping:** `BlobNotFound` (Azure's error code for non-existent
  blobs) is mapped to the standard S3 `NoSuchKey` error.
- **Object Lock:** Not supported. All Object Lock operations return
  HTTP 501 NotImplemented.

**Configuration example:**

```yaml
backend:
  type: azure
  # Endpoint is assembled automatically from the account name if not set:
  azure:
    account_name: "mystorageaccount"
  # or specify the endpoint explicitly:
  # endpoint: "https://mystorageaccount.blob.core.windows.net"
  region: us-east-1
  access_key: "${AZURE_STORAGE_ACCOUNT_NAME}"
  secret_key: "${AZURE_STORAGE_ACCOUNT_KEY}"
```

---

## Choosing a Backend Type

| Backend | Use Case | `backend.type` value |
|---|---|---|
| AWS S3 | Production — primary cloud store | `s3` (default) |
| MinIO | Development / on-premise | `s3` |
| GCS | Google Cloud customers | `gcs` |
| Azure Blob | Azure customers | `azure` |
| Any S3-compatible store | Hetzner, Wasabi, Backblaze, DigitalOcean, etc. | `s3` |
# Backend TLS trust

HTTPS backend connections use the system trust store by default. To trust a
private issuing CA, mount its PEM file and configure `backend.tls.ca_file` (or
`BACKEND_TLS_CA_FILE`). The file is appended to system roots and hostname
verification remains enabled; restart the gateway after changing it.

`backend.tls.insecure_skip_verify` / `BACKEND_TLS_INSECURE_SKIP_VERIFY` is an
explicit diagnostic escape hatch. It disables certificate-chain and hostname
verification while retaining encryption, emits a startup warning, and must not
be used in production. These settings do not make a plaintext
`use_ssl: false` connection secure.
