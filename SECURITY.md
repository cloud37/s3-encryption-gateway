# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.8.x (latest) | ✅ |
| < 0.8 | ❌ |

We provide security fixes for the current minor release only. Older versions do not receive backports.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in the S3 Encryption Gateway, report it privately via one of these channels:

- **GitHub Private Vulnerability Reporting** (preferred):
  [https://github.com/cloud37/s3-encryption-gateway/security/advisories/new](https://github.com/cloud37/s3-encryption-gateway/security/advisories/new)
- **Email**: Open a private advisory via GitHub and we will respond within 48 hours.

### What to Include

A useful report includes:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Affected version(s) and configuration
- Whether you have a suggested fix

### What to Expect

| Timeline | Action |
|---|---|
| **48 hours** | Acknowledgement of your report |
| **7 days** | Initial severity assessment and triage |
| **30 days** | Fix or mitigation for confirmed vulnerabilities |
| **90 days** | Public disclosure (coordinated with reporter) |

We follow responsible disclosure: we will coordinate the publication date with you and credit you in the security advisory unless you prefer to remain anonymous.

## Scope

### In Scope

- Encryption correctness: weaknesses in the AES-256-GCM, ChaCha20-Poly1305, or HKDF-SHA256 implementations
- Key material exposure: any path by which a plaintext DEK or password is logged, leaked over the network, or stored insecurely
- Authentication bypass: weaknesses in AWS Signature V4 validation, admin bearer-token authentication, or rate-limiting
- Metadata integrity: ability to tamper with or substitute encryption metadata without detection
- KMIP/KMS integration: vulnerabilities in the Cosmian KMIP or HSM adapter that could lead to key material exposure
- Container image: critical CVEs in the published `ghcr.io/kenchrcum/s3-encryption-gateway` image
- Privilege escalation in the admin API

### Out of Scope

- Vulnerabilities in the underlying S3 backend (AWS S3, MinIO, etc.)
- Denial of service via legitimate high request volume (rate limiting is a configuration concern)
- Issues requiring physical access to the deployment host
- Security of the operator's own key material management (e.g., a weak password passed to `encryption.password`)

## Security Design

The S3 Encryption Gateway is designed with the following properties:

- **No plaintext at rest**: Objects are encrypted before leaving the gateway process. The S3 backend never sees plaintext data or encryption keys.
- **Per-object keys**: Each object receives a unique DEK. Compromise of a single object's ciphertext reveals nothing about other objects.
- **Authenticated encryption**: AES-256-GCM and ChaCha20-Poly1305 provide both confidentiality and integrity. Tampered ciphertext is detected and rejected before any plaintext is returned.
- **AAD binding**: The encryption algorithm, key version, original size, and content type are cryptographically bound to each ciphertext via Additional Authenticated Data. Metadata substitution attacks are detected.
- **FIPS profile**: Build with `-tags=fips` to restrict all cryptographic operations to FIPS-140 approved algorithms (AES-256-GCM, HKDF-SHA256, PBKDF2-HMAC-SHA256).
- **Key zeroization**: Plaintext DEKs and derived keys are zeroed from memory immediately after use.
- **Constant-time comparisons**: All security-sensitive byte comparisons use `crypto/subtle`.

For the full security architecture, see [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) and [`docs/ENCRYPTION_DESIGN.md`](docs/ENCRYPTION_DESIGN.md).
