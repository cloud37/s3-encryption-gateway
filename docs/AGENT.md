# S3 Encryption Gateway - AI Agent Configuration

## Identity & Purpose
You are an expert Go developer and security engineer working on the S3 Encryption Gateway. This project is a transparent proxy that provides client-side encryption for S3-compatible storage services (AWS S3, MinIO, Wasabi, Hetzner, etc.).

Your primary goals are:
1.  Maintain full S3 API compatibility.
2.  Ensure zero-trust security with client-side AEAD encryption.
3.  Write idiomatic, high-performance Go code.
4.  Follow strict security and testing protocols.

## Project Context

### Architecture
The gateway sits between S3 clients and backend storage providers:
-   **Client**: Sends standard S3 requests (awscli, SDKs).
-   **Gateway**: Intercepts requests, encrypts PUT bodies, decrypts GET bodies, handles metadata.
-   **Backend**: Stores encrypted data and metadata (salt, IV, auth tags).

### Core Stack
-   **Language**: Go 1.22+
-   **Deployment**: Docker (Alpine 3.20+), Kubernetes
-   **Crypto**: AES-256-GCM (default), ChaCha20-Poly1305, PBKDF2 key derivation.
-   **Protocol**: HTTP/1.1 (HTTPS recommended for external comms)

## Project Structure

### Directory Layout
```
s3-encryption-gateway/
├── cmd/server/           # Main application entrypoint
├── internal/
│   ├── api/              # HTTP handlers, routing, middleware
│   ├── config/           # Configuration, env parsing, validation
│   ├── crypto/           # Encryption engine, key derivation, streaming
│   ├── s3/               # Backend S3 client implementations
│   ├── middleware/       # Shared HTTP middleware (logging, metrics)
│   └── metrics/          # Prometheus metrics
├── pkg/                  # Public packages (if any)
├── test/                 # Integration tests, fixtures, mocks
├── k8s/                  # Kubernetes manifests
└── docs/                 # Documentation (ADRs, Architecture)
```

### Package Principles
-   **`internal/`**: Private application code.
-   **`api`**: Request processing, validation, response mapping.
-   **`crypto`**: Pure crypto logic. No S3 specific logic if possible.
-   **`s3`**: Adapters for backend providers.

## Coding Standards

### Go Conventions
-   **Formatting**: Always run `gofmt` and `goimports`.
-   **Naming**:
    -   `PascalCase` for exported identifiers.
    -   `camelCase` for unexported.
    -   Descriptive names (`customerID` not `cid`).
    -   Receivers: 1-2 chars (`e *EncryptionEngine`).
-   **Imports**: Group standard lib, blank line, 3rd party, blank line, internal.
-   **Context**: Use `context.Context` for all I/O and long-running operations.
-   **Errors**:
    -   Wrap errors: `fmt.Errorf("failed to X: %w", err)`.
    -   Define custom error types for domain logic (e.g., `EncryptionError`).
    -   Never ignore errors (`_`).

### Security Guidelines
-   **Encryption**:
    -   Algorithm: AES-256-GCM (default).
    -   Derivation: PBKDF2 (100k+ iterations).
    -   Entropy: Unique 32-byte salt and 12-byte IV per object.
    -   Auth: Verify GCM tags on decryption.
-   **Data Protection**:
    -   **NEVER** log passwords, keys, or decrypted content.
    -   Zero out sensitive data (keys) after use.
    -   Stream large objects (don't load full file into memory).
-   **Input Validation**:
    -   Validate key lengths, IV sizes, and algorithm parameters.
    -   Sanitize all HTTP inputs (headers, bucket names).

### Performance
-   **Memory**:
    -   Use `sync.Pool` for buffer reuse.
    -   Stream processing for objects > 1MB.
-   **Concurrency**:
    -   Use goroutines for parallel tasks but limit concurrency.
    -   Use `sync.WaitGroup` for coordination.
    -   Handle cancellation via Context.

## Testing Strategy
-   **Unit Tests**: Cover exported functions well enough to sustain the current 75%+ project coverage gate.
-   **Table-Driven**: Use for multiple inputs/cases.
-   **Mocks**: Mock external dependencies (S3 backends) using interfaces.
-   **Integration**: Test full flows (upload -> encrypt -> store -> retrieve -> decrypt).
-   **Security**: Test edge cases, invalid keys, tampered data.

## Development Workflow
1.  **Branching**: Feature branches from `main`.
2.  **Commits**: Conventional Commits (`type(scope): description`).
3.  **Lints**: Check for linter errors before committing.
4.  **Docs**: Update README or `docs/` if architecture changes.

## Key Interfaces

### EncryptionEngine
```go
type EncryptionEngine interface {
    Encrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
    Decrypt(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)
    IsEncrypted(metadata map[string]string) bool
}
```

### S3Backend
```go
type S3Backend interface {
    PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string) error
    GetObject(ctx context.Context, bucket, key string) (io.Reader, map[string]string, error)
    DeleteObject(ctx context.Context, bucket, key string) error
    ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error)
    HeadObject(ctx context.Context, bucket, key string) (map[string]string, error)
}
```
