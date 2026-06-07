# Using S3 CLI Tools with s3-encryption-gateway

The gateway implements the S3 API. Any S3-compatible client works against it
without modification, using the gateway's credentials as the AWS access/secret
key pair. This document shows how to configure and use three widely-adopted
tools — `awscli`, `s5cmd`, and `mc` (MinIO Client) — for common operations.

For gateway-specific operations that standard tools cannot perform (inspecting
ciphertext envelopes, auditing key usage, algorithm scanning), see
`docs/MIGRATION.md` and the `s3eg-migrate` binary.

---

## Contents

1. [Gateway Credential Model](#1-gateway-credential-model)
2. [AWS CLI (`awscli`)](#2-aws-cli-awscli)
3. [s5cmd](#3-s5cmd)
4. [MinIO Client (`mc`)](#4-minio-client-mc)
5. [Common Recipes](#5-common-recipes)
6. [Verifying Encryption Is Active](#6-verifying-encryption-is-active)
7. [Tool Comparison](#7-tool-comparison)

---

## 1. Gateway Credential Model

The gateway validates every inbound request against its own credential store
(the `auth.credentials` list in `gateway.yaml`). Think of these as the
gateway's "front door" keys — they are entirely separate from the backend
S3 credentials the gateway uses to talk to MinIO, Garage, etc.

| Config field | Purpose |
|---|---|
| `auth.credentials[].access_key` | Access key presented by the client tool |
| `auth.credentials[].secret_key` | Secret key presented by the client tool |
| `backend.access_key` | Gateway → backend (MinIO/Garage) credential |
| `backend.secret_key` | Gateway → backend (MinIO/Garage) credential |

All examples below use the **client-facing** credentials. The gateway
forwards requests to the backend transparently; the client never needs the
backend credentials.

**Example credential from `gateway.yaml`:**

```yaml
auth:
  credentials:
    - access_key: "my-gateway-access-key"
      secret_key_env: "GW_SECRET_KEY_1"
      label: "dev-client"
```

Throughout this document, replace `my-gateway-access-key` / `changeme` with
the credentials from your `gateway.yaml`.

---

## 2. AWS CLI (`awscli`)

### Installation

```bash
# macOS
brew install awscli

# Linux (official installer)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install

# Via pip
pip install awscli
```

### Configuration

The cleanest approach is a named profile so you do not pollute the default
AWS configuration:

```bash
aws configure --profile gateway
# AWS Access Key ID:     my-gateway-access-key
# AWS Secret Access Key: changeme
# Default region name:   us-east-1
# Default output format: json
```

Or set environment variables for a single session:

```bash
export AWS_ACCESS_KEY_ID=my-gateway-access-key
export AWS_SECRET_ACCESS_KEY=changeme
export AWS_DEFAULT_REGION=us-east-1
```

### Common operations

All examples use `--endpoint-url` to point at the gateway and
`--profile gateway` for credentials. Adjust the endpoint to match your
deployment (local development typically runs on `http://localhost:8080`).

#### List buckets

```bash
aws s3 ls \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

#### List objects in a bucket

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url http://localhost:8080 \
  --profile gateway

# Recursive listing with sizes
aws s3 ls s3://my-bucket/ --recursive --human-readable \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

#### Upload a file

```bash
aws s3 cp /path/to/local/file.txt s3://my-bucket/path/to/object.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway

# With custom metadata
aws s3 cp file.txt s3://my-bucket/file.txt \
  --metadata author=alice,env=prod \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

#### Download a file

```bash
aws s3 cp s3://my-bucket/path/to/object.txt /tmp/downloaded.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway

# Download to stdout
aws s3 cp s3://my-bucket/object.txt - \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

#### Inspect object metadata (head)

```bash
aws s3api head-object \
  --bucket my-bucket \
  --key path/to/object.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

Output includes `ContentLength`, `ContentType`, `ETag`, `Metadata`, and any
`x-amz-meta-*` fields set at upload time.

#### Generate a pre-signed URL

```bash
# GET URL valid for 1 hour (3600 seconds)
aws s3 presign s3://my-bucket/object.txt \
  --expires-in 3600 \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

The returned URL is signed with the gateway credentials and can be shared with
any HTTP client:

```bash
curl "$(aws s3 presign s3://my-bucket/object.txt \
  --expires-in 3600 \
  --endpoint-url http://localhost:8080 \
  --profile gateway)"
```

#### Delete an object

```bash
aws s3 rm s3://my-bucket/object.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

#### Sync a local directory

```bash
aws s3 sync /local/data/ s3://my-bucket/prefix/ \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

### Path-style forcing

Some backends require path-style addressing. Add to your profile in
`~/.aws/config`:

```ini
[profile gateway]
s3 =
  addressing_style = path
```

Or pass `--no-sign-request` is **not** appropriate here — you always want
signed requests so the gateway can authenticate you.

---

## 3. s5cmd

`s5cmd` is a high-performance, parallel S3 client written in Go. It is
significantly faster than `awscli` for bulk operations due to native
concurrency.

### Installation

```bash
# macOS
brew install peak/tap/s5cmd

# Linux (pre-built binary)
curl -L https://github.com/peak/s5cmd/releases/latest/download/s5cmd_Linux_x86_64.tar.gz \
  | tar xz && sudo mv s5cmd /usr/local/bin/

# Via go install
go install github.com/peak/s5cmd/v2@latest
```

### Configuration

`s5cmd` reads from the standard AWS credential chain. Use environment
variables for simplicity:

```bash
export AWS_ACCESS_KEY_ID=my-gateway-access-key
export AWS_SECRET_ACCESS_KEY=changeme
export AWS_REGION=us-east-1
```

Or use a named profile from `~/.aws/credentials` with `--credentials-file`
and `--profile`.

### Common operations

The `--endpoint-url` flag and `--no-verify-ssl` (for HTTP endpoints) are the
key differences from pointing at real AWS.

#### List buckets

```bash
s5cmd --endpoint-url http://localhost:8080 ls
```

#### List objects

```bash
s5cmd --endpoint-url http://localhost:8080 ls s3://my-bucket/

# Recursive
s5cmd --endpoint-url http://localhost:8080 ls 's3://my-bucket/*'
```

#### Upload a file

```bash
s5cmd --endpoint-url http://localhost:8080 cp /local/file.txt s3://my-bucket/file.txt
```

#### Upload a directory (parallel)

```bash
# Uses all CPU cores by default; tune with --numworkers
s5cmd --endpoint-url http://localhost:8080 \
  --numworkers 32 \
  cp '/local/data/*' s3://my-bucket/prefix/
```

#### Download a file

```bash
s5cmd --endpoint-url http://localhost:8080 cp s3://my-bucket/file.txt /tmp/file.txt
```

#### Download a bucket prefix

```bash
s5cmd --endpoint-url http://localhost:8080 cp 's3://my-bucket/prefix/*' /local/output/
```

#### Delete objects

```bash
s5cmd --endpoint-url http://localhost:8080 rm s3://my-bucket/file.txt

# Delete all objects under a prefix
s5cmd --endpoint-url http://localhost:8080 rm 's3://my-bucket/prefix/*'
```

#### Run commands from a file

`s5cmd` supports a batch mode for maximum throughput:

```bash
cat commands.txt
# cp s3://source/a.txt s3://dest/a.txt
# cp s3://source/b.txt s3://dest/b.txt

s5cmd --endpoint-url http://localhost:8080 run commands.txt
```

### TLS / self-signed certificates

```bash
# Skip TLS verification (dev only)
s5cmd --endpoint-url https://gateway.internal:443 \
  --no-verify-ssl \
  ls s3://my-bucket/

# Use a custom CA bundle
AWS_CA_BUNDLE=/path/to/ca.pem s5cmd --endpoint-url https://gateway.internal:443 ls
```

---

## 4. MinIO Client (`mc`)

`mc` is the official MinIO command-line client and works with any
S3-compatible endpoint.

### Installation

```bash
# macOS
brew install minio/stable/mc

# Linux
curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc && sudo mv mc /usr/local/bin/

# Via go install
go install github.com/minio/mc@latest
```

### Configuration

`mc` uses named *aliases* rather than AWS profiles:

```bash
mc alias set gateway \
  http://localhost:8080 \
  my-gateway-access-key \
  changeme \
  --api S3v4
```

The alias `gateway` is used in all subsequent commands. You can create
multiple aliases for different environments (dev, staging, prod).

### Common operations

#### List buckets

```bash
mc ls gateway
```

#### List objects

```bash
mc ls gateway/my-bucket

# Recursive
mc ls --recursive gateway/my-bucket
```

#### Upload a file

```bash
mc cp /local/file.txt gateway/my-bucket/file.txt
```

#### Upload a directory (parallel)

```bash
mc cp --recursive /local/data/ gateway/my-bucket/prefix/
```

#### Download a file

```bash
mc cp gateway/my-bucket/file.txt /tmp/file.txt
```

#### Download to stdout

```bash
mc cat gateway/my-bucket/file.txt
```

#### Inspect object metadata (stat)

```bash
mc stat gateway/my-bucket/file.txt
```

Output includes size, last modified, ETag, content type, and all custom
metadata fields.

#### Delete an object

```bash
mc rm gateway/my-bucket/file.txt

# Delete all objects under a prefix
mc rm --recursive --force gateway/my-bucket/prefix/
```

#### Mirror a local directory

```bash
mc mirror /local/data/ gateway/my-bucket/prefix/
```

#### Watch for changes (tail-like streaming)

```bash
mc watch gateway/my-bucket
```

#### Create a bucket

```bash
mc mb gateway/new-bucket
```

#### Generate a pre-signed URL

```bash
# GET URL valid for 1 hour
mc share download --expire 1h gateway/my-bucket/file.txt

# PUT URL (upload via presigned link)
mc share upload --expire 1h gateway/my-bucket/upload-target.txt
```

---

## 5. Common Recipes

### Round-trip smoke test (verify the gateway is working)

```bash
# Write a known value
echo "hello gateway" | \
  aws s3 cp - s3://my-bucket/smoke-test.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway

# Read it back
aws s3 cp s3://my-bucket/smoke-test.txt - \
  --endpoint-url http://localhost:8080 \
  --profile gateway
# Expected output: hello gateway

# Clean up
aws s3 rm s3://my-bucket/smoke-test.txt \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

### Upload with metadata and verify round-trip

```bash
aws s3 cp document.pdf s3://my-bucket/docs/document.pdf \
  --metadata "author=alice,classification=internal,version=2" \
  --content-type "application/pdf" \
  --endpoint-url http://localhost:8080 \
  --profile gateway

# Verify metadata was preserved
aws s3api head-object \
  --bucket my-bucket \
  --key docs/document.pdf \
  --endpoint-url http://localhost:8080 \
  --profile gateway \
  --query 'Metadata'
```

### Benchmark throughput (s5cmd)

```bash
# Generate 100 × 1 MB test files
mkdir -p /tmp/bench && for i in $(seq 1 100); do
  dd if=/dev/urandom of=/tmp/bench/file-$i.bin bs=1M count=1 2>/dev/null
done

# Upload with 32 workers and measure wall time
time s5cmd --endpoint-url http://localhost:8080 \
  --numworkers 32 \
  cp '/tmp/bench/*' s3://my-bucket/bench/

# Clean up
s5cmd --endpoint-url http://localhost:8080 rm 's3://my-bucket/bench/*'
```

### Pre-signed URL workflow

```bash
# Generate a 15-minute presigned GET URL
PRESIGNED=$(aws s3 presign s3://my-bucket/report.pdf \
  --expires-in 900 \
  --endpoint-url http://localhost:8080 \
  --profile gateway)

echo "Share this URL (valid 15 minutes):"
echo "$PRESIGNED"

# Any HTTP client can fetch it without credentials
curl -o /tmp/report.pdf "$PRESIGNED"
```

### Sync with delete (mirror)

```bash
# Sync local directory to gateway; delete objects absent locally
aws s3 sync /local/data/ s3://my-bucket/data/ \
  --delete \
  --endpoint-url http://localhost:8080 \
  --profile gateway
```

---

## 6. Verifying Encryption Is Active

Standard S3 tools interact with the gateway at the plaintext level — they
send and receive unencrypted content, and the gateway handles encryption
transparently. To confirm that encryption is actually being applied, check
**the backend directly** (bypassing the gateway) and inspect the raw object.

### Option A — Inspect via backend credentials (MinIO/Garage)

Configure a second alias/profile pointing **directly at the backend** using
the backend's own credentials (`backend.access_key` / `backend.secret_key`
from `gateway.yaml`):

```bash
# Direct backend alias (MinIO example)
mc alias set backend \
  http://minio:9000 \
  BACKEND_ACCESS_KEY \
  BACKEND_SECRET_KEY

# Fetch the raw backend object — should be binary ciphertext, not plaintext
mc cat backend/my-bucket/my-object.txt | head -c 64 | xxd
```

If the gateway is working correctly, the raw backend bytes are ciphertext
(random-looking binary), not the original plaintext content.

### Option B — Use `s3eg-cli inspect` (gateway-aware)

The `s3eg-cli` binary (see `docs/MIGRATION.md`) includes an `inspect`
sub-command that decodes the encryption envelope from the backend object and
reports the algorithm, key ID, IV, and AAD scheme without requiring you to
configure direct backend access:

```bash
s3eg-cli inspect \
  --config gateway.yaml \
  my-bucket \
  path/to/object.txt
```

Output (example):

```
Bucket:          my-bucket
Key:             path/to/object.txt
Encrypted:       true
Class:           modern
AAD Scheme:      v2-aad
Algorithm:       AES256-GCM
Key Version:     1
Salt (hex):      a1b2c3d4...
IV (hex):        e5f60718...
Ciphertext head: 293a4b5c...
```

This is the authoritative way to verify encryption without direct backend
access.

### What the ETag tells you

The ETag returned by the gateway for an encrypted object is an HMAC of the
ciphertext — it will differ from the MD5 of the plaintext. This is expected
and correct behaviour. Do not use ETag equality between gateway and backend
to validate encryption; use the `s3eg-cli inspect` sub-command instead.

---

## 7. Tool Comparison

| Feature | `awscli` | `s5cmd` | `mc` |
|---|---|---|---|
| Pre-signed URLs | `aws s3 presign` | — | `mc share download` |
| Parallel upload | Limited (`--sse`, `--multipart-threshold`) | Native (`--numworkers`) | Native (`--parallel`) |
| Object metadata (head) | `aws s3api head-object` | — | `mc stat` |
| Recursive copy | `aws s3 cp --recursive` | `cp 's3://…/*'` | `mc cp --recursive` |
| Sync with delete | `aws s3 sync --delete` | — | `mc mirror` |
| Watch/events | — | — | `mc watch` |
| Batch from file | — | `s5cmd run` | — |
| Path-style forcing | `s3.addressing_style=path` | Default | Default |
| Throughput (bulk) | Moderate | Highest | High |
| Installation | Large (Python) | Single binary | Single binary |

**Recommendation by use case:**

- **Ad hoc inspection, presigned URLs, metadata** → `awscli` (most familiar, richest API coverage)
- **Bulk upload/download, CI pipelines, benchmarking** → `s5cmd` (fastest, lowest overhead)
- **Interactive exploration, watch, mirror** → `mc` (best UX for day-to-day work)
- **Encryption audit, key inspection, algorithm scan** → `s3eg-cli` (only tool that understands gateway internals)
