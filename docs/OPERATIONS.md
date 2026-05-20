# Operations Guide

## Metadata Encryption Key Management

### Overview

The gateway supports encrypting encryption/compression metadata at rest using
a separate key (distinct from the data encryption password/KMS key). This
prevents S3-only attackers from reading metadata such as the encryption
algorithm, salt, and IV.

### Key Generation

Generate a 32-byte (256-bit) AES key and encode it in base64:

```bash
openssl rand -base64 32
```

Example output:
```
uL8vE8zYq3Fp5s7Wx2Rc9BnM4Kj6Ht0GdA1bC5eFgIw=
```

### File-Based Key

Place the generated key in a file with restricted permissions:

```bash
echo "uL8vE8zYq3Fp5s7Wx2Rc9BnM4Kj6Ht0GdA1bC5eFgIw=" > /etc/s3eg/metadata-master.key
chmod 600 /etc/s3eg/metadata-master.key
chown s3eg:s3eg /etc/s3eg/metadata-master.key
```

Configure the gateway:

```yaml
encryption:
  metadata_encryption_key_file: /etc/s3eg/metadata-master.key
```

Or via environment variable:

```bash
ENCRYPTION_METADATA_KEY_FILE=/etc/s3eg/metadata-master.key
```

### Inline Key (SHA-256 Hashed)

Provide the key directly in configuration (minimum 128 characters to activate
SHA-256 hashing):

```yaml
encryption:
  metadata_encryption_key: "your-very-long-secret-that-is-at-least-128-characters-long-for-security-purposes..."
```

Or via environment:

```bash
ENCRYPTION_METADATA_KEY="your-very-long-secret..."
```

> **Security note:** Inline keys are subject to secret leakage through config
> dumps, process listings, and log files. Prefer file-based or KMS-wrapped keys
> in production.

### KMS Wrapping

If the gateway is configured with a Key Manager (KMS provider), the metadata
key is automatically wrapped using the Key Manager's `WrapKey` operation.
Configure via:

```yaml
encryption:
  kms:
    enabled: true
    # ... KMS-specific settings
```

The gateway will:
1. Read the raw metadata key as a file or inline value.
2. Wrap it through the Key Manager at startup.
3. Store the wrapped envelope in memory.
4. Use the Key Manager's `UnwrapKey` to retrieve the plaintext key at runtime.

### Key Loss Recovery

**There is no recovery if the metadata encryption key is lost.**

If the key is lost:
- Objects encrypted with metadata encryption **cannot be decrypted**.
- The encryption metadata (algorithm, salt, IV, original size) is
  cryptographically sealed and irrecoverable.
- Data itself remains encrypted with the data encryption key, but the
  parameters needed to decrypt it are inside the sealed blob.

**Backup procedures are mandatory.**

### Backup Procedures

1. **Store the key offline** — write to a password manager, encrypted USB
   drive, or HSM backup.
2. **Use your secret management system** — HashiCorp Vault, AWS Secrets
   Manager, or Kubernetes Secrets.
3. **Include the key in incident recovery documentation** — ensure on-call
   engineers know where to find it.

### Key Rotation

Key rotation is not supported in the initial implementation. To rotate the
metadata key:
1. Enable the new key in the gateway configuration.
2. All **new** objects will use the new key.
3. **Existing** objects will remain encrypted with the old key.
4. To re-encrypt existing objects, use the migration tool (future work).

### Monitoring

The following metrics are available for metadata encryption operations
(added alongside the feature):

| Metric | Type | Description |
|---|---|---|
| `gateway_metadata_encrypt_total` | Counter | Total metadata encryption operations |
| `gateway_metadata_decrypt_total` | Counter | Total metadata decryption operations |
| `gateway_metadata_encrypt_errors_total` | Counter | Metadata encryption failures |
| `gateway_metadata_decrypt_errors_total` | Counter | Metadata decryption failures |

### Validation

Verify the feature is working:

```bash
# Upload a test object
aws s3 cp /tmp/test.txt s3://your-bucket/test.txt

# Check that the encrypted metadata header exists
aws s3api head-object --bucket your-bucket --key test.txt | grep x-amz-meta-enc-metadata
```

If `x-amz-meta-enc-metadata` is present, metadata encryption is active.
