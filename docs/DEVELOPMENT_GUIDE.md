# S3 Encryption Gateway - Development Guide

## Overview

This guide provides comprehensive instructions for developing the S3 Encryption Gateway. Follow this guide to ensure consistent development practices and maintain code quality.

## Development Environment Setup

### Prerequisites

#### Required Software
- **Go 1.22+**: Core programming language (latest stable)
- **Docker**: Containerization platform (latest stable)
- **kubectl**: Kubernetes CLI (for deployment testing)
- **MinIO**: Local S3-compatible server for testing
- **git**: Version control (latest stable)
- **make**: Build automation

#### Installation Commands
```bash
# Install Go (Ubuntu/Debian)
sudo apt update
sudo apt install golang-go

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install MinIO client
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/
```

### Project Setup

#### Clone and Initialize
```bash
git clone https://github.com/your-org/s3-encryption-gateway.git
cd s3-encryption-gateway

# Initialize Go modules
go mod tidy

# Create local development configuration
cp config.example.yaml config.local.yaml
```

#### Development Tools Setup
```bash
# Install development tools (specific versions)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2
go install github.com/air-verse/air@v1.49.0  # Live reload
go install github.com/go-delve/delve/cmd/dlv@v1.22.0  # Debugger
go install golang.org/x/vuln/cmd/govulncheck@v1.0.4  # Vulnerability scanner

# Optional: Install additional tools
go install honnef.co/go/tools/cmd/staticcheck@v0.4.6  # Advanced static analysis
go install github.com/uudashr/gopkgs/v2/cmd/gopkgs@v2.1.0  # Go packages listing
```

## Project Structure

### Directory Layout
```
s3-encryption-gateway/
├── cmd/                    # Application entrypoints
│   └── server/            # Main server application
├── internal/              # Private application code
│   ├── api/              # HTTP handlers and routing
│   ├── config/           # Configuration management
│   ├── crypto/           # Encryption/decryption logic
│   ├── s3/               # S3 client and operations
│   ├── middleware/       # HTTP middleware
│   └── metrics/          # Monitoring and metrics
├── pkg/                  # Public packages (if any)
├── test/                 # Test utilities and data
├── docs/                 # Documentation
├── k8s/                  # Kubernetes manifests
├── docker/               # Docker-related files
├── .github/              # GitHub Actions and templates
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── DEVELOPMENT_GUIDE.md
```

### Package Organization Principles

#### Internal Packages
- **api**: HTTP request/response handling, routing
- **config**: Configuration parsing, validation, environment handling
- **crypto**: All encryption/decryption operations
- **s3**: Backend S3 client implementations, request parsing
- **middleware**: HTTP middleware for logging, auth, etc.
- **metrics**: Prometheus metrics, health checks

#### Code Organization Rules
- **Single responsibility**: Each package has one clear purpose
- **Dependency direction**: Lower-level packages don't import higher-level ones
- **Interface segregation**: Define interfaces for external dependencies
- **Error handling**: Centralized error types and handling

## Configuration Schema

This section provides comprehensive documentation for all configuration options available in the S3 Encryption Gateway. Configuration can be provided via YAML file and/or environment variables, with environment variables taking precedence.

### Global Configuration

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `listen_addr` | string | `:8080` | `LISTEN_ADDR` | HTTP server listen address (host:port) |
| `log_level` | string | `info` | `LOG_LEVEL` | Logging level (debug, info, warn, error) |
| `proxied_bucket` | string | - | `PROXIED_BUCKET` | Optional: Restrict proxying to this specific bucket only |

### Backend Configuration (`backend`)

S3-compatible backend storage configuration.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `endpoint` | string | - | `BACKEND_ENDPOINT` | S3-compatible API endpoint URL |
| `region` | string | `us-east-1` | `BACKEND_REGION` | AWS region or provider-specific region |
| `access_key` | string | - | `BACKEND_ACCESS_KEY` | Backend access key (required unless `use_client_credentials` is true) |
| `secret_key` | string | - | `BACKEND_SECRET_KEY` | Backend secret key (required unless `use_client_credentials` is true) |
| `provider` | string | - | `BACKEND_PROVIDER` | Provider name for reference (aws, minio, wasabi, hetzner, etc.) |
| `use_ssl` | bool | `true` | `BACKEND_USE_SSL` | Use HTTPS for backend connections |
| `use_path_style` | bool | `false` | `BACKEND_USE_PATH_STYLE` | Use path-style URLs instead of virtual-hosted style |
| `filter_metadata_keys` | []string | - | `BACKEND_FILTER_METADATA_KEYS` | Comma-separated list of metadata keys to filter out |
| `use_client_credentials` | bool | `false` | `BACKEND_USE_CLIENT_CREDENTIALS` | Extract and use credentials from client requests. **Note**: Only query parameter authentication (`?AWSAccessKeyId=...&AWSSecretAccessKey=...`) is supported. AWS Signature V4 (Authorization header) is NOT supported when this is enabled. |

**Provider Examples:**

```yaml
# AWS S3
backend:
  endpoint: "https://s3.amazonaws.com"
  region: "us-west-2"
  provider: "aws"

# MinIO
backend:
  endpoint: "http://localhost:9000"
  region: "us-east-1"
  provider: "minio"
  use_ssl: false

# Wasabi
backend:
  endpoint: "https://s3.wasabisys.com"
  region: "us-east-1"
  provider: "wasabi"

# Hetzner
backend:
  endpoint: "https://fsn1.your-objectstorage.com"
  region: "fsn1"
  provider: "hetzner"
```

### Encryption Configuration (`encryption`)

Client-side encryption settings.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `password` | string | - | `ENCRYPTION_PASSWORD` | Encryption password/key (required) |
| `key_file` | string | - | `ENCRYPTION_KEY_FILE` | Path to key file (alternative to password) |
| `preferred_algorithm` | string | `AES256-GCM` | `ENCRYPTION_PREFERRED_ALGORITHM` | Preferred encryption algorithm |
| `supported_algorithms` | []string | `[AES256-GCM, ChaCha20-Poly1305]` | `ENCRYPTION_SUPPORTED_ALGORITHMS` | Comma-separated list of supported algorithms |
| `chunked_mode` | bool | `true` | `ENCRYPTION_CHUNKED_MODE` | Enable chunked/streaming encryption |
| `chunk_size` | int | `65536` | `ENCRYPTION_CHUNK_SIZE` | Chunk size in bytes (16KB-1MB) |

**Algorithm Options:**
- `AES256-GCM`: AES-256 with Galois/Counter Mode (authenticated encryption)
- `ChaCha20-Poly1305`: ChaCha20 stream cipher with Poly1305 authentication

```yaml
# Basic encryption setup
encryption:
  password: "your-secure-password-here"
  preferred_algorithm: "AES256-GCM"
  supported_algorithms:
    - "AES256-GCM"
    - "ChaCha20-Poly1305"
  chunked_mode: true
  chunk_size: 65536  # 64KB chunks

# Key file authentication
encryption:
  key_file: "/path/to/encryption.key"
  preferred_algorithm: "AES256-GCM"
```

### Key Manager Configuration (`encryption.key_manager`)

Key management and rotation settings.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `KEY_MANAGER_ENABLED` | Enable key rotation/KMS mode |

```yaml
# Enable key management (future feature)
encryption:
  key_manager:
    enabled: false  # Currently single password mode only
```

### Compression Configuration (`compression`)

Optional compression before encryption.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `COMPRESSION_ENABLED` | Enable compression before encryption |
| `min_size` | int64 | `1024` | `COMPRESSION_MIN_SIZE` | Minimum object size for compression (bytes) |
| `content_types` | []string | `[text/plain, application/json, application/xml]` | `COMPRESSION_CONTENT_TYPES` | Content types to compress |
| `algorithm` | string | `gzip` | `COMPRESSION_ALGORITHM` | Compression algorithm (gzip only) |
| `level` | int | `6` | `COMPRESSION_LEVEL` | Compression level (1-9, gzip-specific) |

```yaml
# Enable compression for text-based content
compression:
  enabled: true
  min_size: 1024  # Only compress objects > 1KB
  content_types:
    - "text/plain"
    - "application/json"
    - "application/xml"
    - "text/html"
    - "application/javascript"
  algorithm: "gzip"
  level: 6  # Balanced compression ratio/speed
```

### Server Configuration (`server`)

HTTP server settings and timeouts.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `read_timeout` | duration | `0` (disabled) | `SERVER_READ_TIMEOUT` | Max time to read entire request; keep disabled — use `read_header_timeout` for slow-loris protection |
| `write_timeout` | duration | `0` (disabled) | `SERVER_WRITE_TIMEOUT` | Max time to write response; keep disabled for large object streaming |
| `idle_timeout` | duration | `60s` | `SERVER_IDLE_TIMEOUT` | Maximum idle connection time |
| `read_header_timeout` | duration | `10s` | `SERVER_READ_HEADER_TIMEOUT` | Time to read request headers |
| `max_header_bytes` | int | `1048576` | `SERVER_MAX_HEADER_BYTES` | Maximum header size (bytes) |
| `disable_multipart_uploads` | bool | `false` | `SERVER_DISABLE_MULTIPART_UPLOADS` | Disable multipart uploads entirely |

**Duration Format:** Go duration strings (e.g., `30s`, `5m`, `1h30m`)

```yaml
# Production server settings
server:
  read_timeout: "0s"   # Disabled; read_header_timeout guards slow-loris; non-zero kills large object streams
  write_timeout: "0s"  # Disabled; gateway streams arbitrarily large S3 objects
  idle_timeout: "120s"
  read_header_timeout: "10s"
  max_header_bytes: 1048576  # 1MB
  disable_multipart_uploads: false
```

### TLS Configuration (`tls`)

HTTPS/TLS settings.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `TLS_ENABLED` | Enable HTTPS/TLS |
| `cert_file` | string | - | `TLS_CERT_FILE` | Path to TLS certificate file |
| `key_file` | string | - | `TLS_KEY_FILE` | Path to TLS private key file |

```yaml
# Enable TLS
tls:
  enabled: true
  cert_file: "/etc/ssl/certs/gateway.crt"
  key_file: "/etc/ssl/private/gateway.key"
```

### Rate Limiting Configuration (`rate_limit`)

Request rate limiting.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `RATE_LIMIT_ENABLED` | Enable rate limiting |
| `limit` | int | `100` | `RATE_LIMIT_REQUESTS` | Maximum requests per time window |
| `window` | duration | `60s` | `RATE_LIMIT_WINDOW` | Time window for rate limiting |

```yaml
# Rate limiting (100 requests per minute)
rate_limit:
  enabled: true
  limit: 100
  window: "60s"
```

### Cache Configuration (`cache`)

In-memory caching for encrypted objects.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `CACHE_ENABLED` | Enable in-memory caching |
| `max_size` | int64 | `104857600` | `CACHE_MAX_SIZE` | Maximum cache size (bytes) |
| `max_items` | int | `1000` | `CACHE_MAX_ITEMS` | Maximum number of cached items |
| `default_ttl` | duration | `5m` | `CACHE_DEFAULT_TTL` | Default time-to-live for cache entries |

```yaml
# Enable caching for frequently accessed objects
cache:
  enabled: true
  max_size: 1073741824  # 1GB
  max_items: 5000
  default_ttl: "10m"
```

### Audit Configuration (`audit`)

Audit logging for compliance.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `AUDIT_ENABLED` | Enable audit logging |
| `max_events` | int | `10000` | `AUDIT_MAX_EVENTS` | Maximum audit events to keep in memory |

```yaml
# Enable audit logging
audit:
  enabled: true
  max_events: 50000
```

### Tracing Configuration (`tracing`)

OpenTelemetry distributed tracing.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `enabled` | bool | `false` | `TRACING_ENABLED` | Enable distributed tracing |
| `service_name` | string | `s3-encryption-gateway` | `TRACING_SERVICE_NAME` | Service name for traces |
| `service_version` | string | `dev` | `TRACING_SERVICE_VERSION` | Service version |
| `exporter` | string | `stdout` | `TRACING_EXPORTER` | Trace exporter (stdout, jaeger, otlp) |
| `jaeger_endpoint` | string | - | `TRACING_JAEGER_ENDPOINT` | Jaeger collector endpoint |
| `otlp_endpoint` | string | - | `TRACING_OTLP_ENDPOINT` | OTLP gRPC endpoint |
| `sampling_ratio` | float64 | `1.0` | `TRACING_SAMPLING_RATIO` | Sampling ratio (0.0-1.0) |
| `redact_sensitive` | bool | `true` | `TRACING_REDACT_SENSITIVE` | Redact sensitive data in spans |

```yaml
# Jaeger tracing
tracing:
  enabled: true
  service_name: "s3-encryption-gateway"
  service_version: "v1.0.0"
  exporter: "jaeger"
  jaeger_endpoint: "http://jaeger:14268/api/traces"
  sampling_ratio: 0.1  # 10% sampling
  redact_sensitive: true

# OTLP tracing
tracing:
  enabled: true
  service_name: "s3-encryption-gateway"
  exporter: "otlp"
  otlp_endpoint: "otel-collector:4317"
  sampling_ratio: 0.05  # 5% sampling
```

### Logging Configuration (`logging`)

Access logging settings.

| Field | Type | Default | Environment Variable | Description |
|-------|------|---------|---------------------|-------------|
| `access_log_format` | string | `default` | `LOGGING_ACCESS_LOG_FORMAT` | Access log format (default, json, clf) |
| `redact_headers` | []string | `[authorization, x-amz-security-token, x-amz-signature, x-encryption-key, x-encryption-password]` | `LOGGING_REDACT_HEADERS` | Headers to redact in access logs |

```yaml
# JSON access logging with custom redaction
logging:
  access_log_format: "json"
  redact_headers:
    - "authorization"
    - "x-amz-security-token"
    - "x-amz-signature"
    - "x-encryption-key"
    - "x-encryption-password"
    - "x-custom-auth"
```

### Complete Configuration Example

```yaml
# Complete configuration example for production deployment
listen_addr: ":8443"
log_level: "info"
proxied_bucket: ""  # Optional bucket restriction

backend:
  endpoint: "https://s3.us-west-2.amazonaws.com"
  region: "us-west-2"
  access_key: ""  # Set via BACKEND_ACCESS_KEY
  secret_key: ""  # Set via BACKEND_SECRET_KEY
  provider: "aws"
  use_ssl: true
  use_path_style: false
  filter_metadata_keys: []
  use_client_credentials: false

encryption:
  password: ""  # Set via ENCRYPTION_PASSWORD
  preferred_algorithm: "AES256-GCM"
  supported_algorithms:
    - "AES256-GCM"
    - "ChaCha20-Poly1305"
  chunked_mode: true
  chunk_size: 65536
  key_manager:
    enabled: false

compression:
  enabled: true
  min_size: 1024
  content_types:
    - "text/plain"
    - "application/json"
    - "application/xml"
    - "text/html"
  algorithm: "gzip"
  level: 6

server:
  read_timeout: "0s"   # Disabled; read_header_timeout guards slow-loris
  write_timeout: "0s"  # Disabled; required for large object streaming
  idle_timeout: "120s"
  read_header_timeout: "10s"
  max_header_bytes: 1048576
  disable_multipart_uploads: false

tls:
  enabled: true
  cert_file: "/etc/ssl/certs/gateway.crt"
  key_file: "/etc/ssl/private/gateway.key"

rate_limit:
  enabled: true
  limit: 1000
  window: "60s"

cache:
  enabled: true
  max_size: 1073741824  # 1GB
  max_items: 5000
  default_ttl: "10m"

audit:
  enabled: true
  max_events: 50000

tracing:
  enabled: true
  service_name: "s3-encryption-gateway"
  service_version: "v1.0.0"
  exporter: "otlp"
  otlp_endpoint: "otel-collector:4317"
  sampling_ratio: 0.1
  redact_sensitive: true

logging:
  access_log_format: "json"
  redact_headers:
    - "authorization"
    - "x-amz-security-token"
    - "x-amz-signature"
    - "x-encryption-key"
    - "x-encryption-password"
```

### Environment Variables Only Example

```bash
# Minimal configuration using environment variables only
export LISTEN_ADDR=":8080"
export LOG_LEVEL="info"
export BACKEND_ENDPOINT="https://s3.amazonaws.com"
export BACKEND_REGION="us-east-1"
export BACKEND_ACCESS_KEY="your-access-key"
export BACKEND_SECRET_KEY="your-secret-key"
export ENCRYPTION_PASSWORD="your-encryption-password"
export TLS_ENABLED="true"
export TLS_CERT_FILE="/path/to/cert.pem"
export TLS_KEY_FILE="/path/to/key.pem"
```

### Configuration Validation

The gateway validates configuration on startup and provides detailed error messages for invalid settings:

- **Required fields**: `listen_addr`, encryption password or key file, backend credentials (unless using client credentials)
- **Valid ranges**: Log levels, algorithm names, chunk sizes (16KB-1MB), sampling ratios (0.0-1.0)
- **Dependencies**: TLS requires certificate and key files, tracing exporters require endpoints
- **Security**: Sensitive values are not logged in validation errors

### Configuration Hot-Reload

The gateway supports hot-reloading of non-crypto configuration settings via SIGHUP signal or file watcher. Crypto settings (passwords, algorithms, chunking) require restart to change.

**Reloadable Settings:**
- Server timeouts and limits
- Rate limiting
- Caching
- Auditing
- Tracing
- Logging
- TLS settings (certificate rotation)

**Non-reloadable Settings:**
- Encryption passwords/keys
- Encryption algorithms
- Chunked mode settings
- Backend provider/endpoint
- Compression settings

## Coding Standards

### Go Code Style

#### Formatting and Style
```go
// Use gofmt and goimports
go fmt ./...
goimports -w .

// Follow standard Go naming conventions
type S3Request struct {  // PascalCase for exported types
    bucket string       // camelCase for unexported fields
    Key    string       // PascalCase for exported fields
}

// Use meaningful variable names
var encryptionKey []byte  // Good
var k []byte             // Bad

// Group imports: standard, third-party, internal
import (
    "context"
    "io"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/prometheus/client_golang/prometheus"

    "github.com/your-org/s3-gateway/internal/config"
)
```

#### Error Handling
```go
// Use custom error types
type EncryptionError struct {
    Op   string
    Err  error
    Meta map[string]interface{}
}

func (e *EncryptionError) Error() string {
    return fmt.Sprintf("encryption %s failed: %v", e.Op, e.Err)
}

// Wrap errors with context
return fmt.Errorf("failed to encrypt object %s/%s: %w", bucket, key, err)

// Use error handling patterns
func processObject(ctx context.Context, bucket, key string) error {
    data, err := s3Client.GetObject(ctx, bucket, key)
    if err != nil {
        return fmt.Errorf("failed to get object: %w", err)
    }
    defer data.Body.Close()

    encrypted, err := crypto.Encrypt(data.Body)
    if err != nil {
        return fmt.Errorf("failed to encrypt object: %w", err)
    }

    return s3Client.PutObject(ctx, bucket, key, encrypted)
}
```

#### Concurrency Patterns
```go
// Use context for cancellation
func (s *Server) handleRequest(ctx context.Context, req *S3Request) error {
    // Check for cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }

    // Use goroutines with proper error handling
    errCh := make(chan error, 1)
    go func() {
        defer close(errCh)
        errCh <- s.processEncryption(ctx, req)
    }()

    select {
    case err := <-errCh:
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}

// Use sync.WaitGroup for coordination
func encryptBatch(ctx context.Context, objects []*S3Object) error {
    var wg sync.WaitGroup
    errCh := make(chan error, len(objects))

    for _, obj := range objects {
        wg.Add(1)
        go func(o *S3Object) {
            defer wg.Done()
            if err := s.encryptObject(ctx, o); err != nil {
                select {
                case errCh <- err:
                default:
                }
            }
        }(obj)
    }

    wg.Wait()
    close(errCh)

    // Return first error if any
    for err := range errCh {
        return err
    }
    return nil
}
```

### Testing Standards

#### Unit Test Structure
```go
func TestEncryptionEngine_Encrypt(t *testing.T) {
    tests := []struct {
        name     string
        input    []byte
        password string
        wantErr  bool
    }{
        {
            name:     "valid encryption",
            input:    []byte("test data"),
            password: "test-password",
            wantErr:  false,
        },
        {
            name:     "empty password",
            input:    []byte("test data"),
            password: "",
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            engine := NewEncryptionEngine(tt.password)

            reader := bytes.NewReader(tt.input)
            encrypted, err := engine.Encrypt(reader)

            if tt.wantErr {
                assert.Error(t, err)
                return
            }

            assert.NoError(t, err)
            assert.NotNil(t, encrypted)

            // Test decryption
            decrypted, err := engine.Decrypt(encrypted)
            assert.NoError(t, err)

            result, err := io.ReadAll(decrypted)
            assert.NoError(t, err)
            assert.Equal(t, tt.input, result)
        })
    }
}
```

#### Integration Test Setup
```go
func TestS3Gateway_EndToEnd(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    // Setup MinIO test server
    minioServer := testutils.StartMinIOServer(t)
    defer minioServer.Close()

    // Create gateway client
    gateway := testutils.StartGateway(t, GatewayConfig{
        BackendURL: minioServer.URL,
        Password:   "test-password",
    })
    defer gateway.Close()

    // Test S3 operations
    client := s3client.New(gateway.URL)

    // Put encrypted object
    err := client.PutObject("test-bucket", "test-key", []byte("secret data"))
    assert.NoError(t, err)

    // Get and verify decryption
    data, err := client.GetObject("test-bucket", "test-key")
    assert.NoError(t, err)
    assert.Equal(t, []byte("secret data"), data)
}
```

#### Test Coverage Requirements
- **Unit tests**: maintain the current 75%+ project coverage gate and raise it over time
- **Integration tests**: Cover all major S3 operations
- **Performance tests**: Benchmark encryption/decryption speeds
- **Security tests**: Test encryption correctness and error handling

## Development Workflow

### Git Workflow

#### Branch Strategy
```
main                    # Production-ready code
├── feature/encrypt-*   # Feature branches
├── bugfix/*           # Bug fixes
├── refactor/*         # Code refactoring
└── release/v*         # Release branches
```

#### Commit Message Format
```
type(scope): description

[optional body]

[optional footer]

Types: feat, fix, docs, style, refactor, test, chore
Scopes: api, crypto, s3, config, middleware
```

#### Example Commits
```
feat(crypto): implement AES-256-GCM encryption

Add encryption engine with streaming support for large objects.
Includes key derivation using PBKDF2 and metadata handling.

Closes #123

fix(s3): handle multipart upload encryption

Fix issue where multipart uploads were not properly encrypted
due to missing part metadata tracking.
```

### Code Review Process

#### Pull Request Requirements
- **Description**: Clear description of changes and rationale
- **Tests**: All tests pass, new tests added for new features
- **Documentation**: Updated if API or behavior changes
- **Security**: Security review for crypto-related changes
- **Performance**: No significant performance regressions

#### Review Checklist
- [ ] Code compiles and tests pass
- [ ] No linting errors
- [ ] Security vulnerabilities checked
- [ ] Documentation updated
- [ ] Performance impact assessed
- [ ] Error handling appropriate
- [ ] Logging adequate
- [ ] Configuration changes backward compatible

### Build and Release Process

#### Local Development Build
```bash
# Build for local development
make build

# Run with live reload
make dev

# Run tests
make test

# Run linting
make lint

# Run security scan
make security-scan
```

#### CI/CD Pipeline
```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4.1.1
    - uses: actions/setup-go@v5.0.0
      with:
        go-version: '1.22'
    - name: Run tests
      run: make test
    - name: Run linting
      run: make lint
    - name: Security scan
      run: make security-scan
    - name: Build
      run: make build
```

#### Release Process
```bash
# Create release branch
git checkout -b release/v1.0.0

# Update version
echo "v1.0.0" > VERSION

# Tag release
git tag -a v1.0.0 -m "Release version 1.0.0"

# Push release
git push origin release/v1.0.0
git push origin v1.0.0
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
**Priority**: High
**Goals**: Basic proxy functionality without encryption

Tasks:
- [ ] Set up project structure and basic Go modules
- [ ] Implement basic HTTP server with routing
- [ ] Create S3 client for backend communication
- [ ] Add configuration management
- [ ] Implement health checks and basic middleware
- [ ] Set up logging and error handling
- [ ] Create Docker container and basic Kubernetes deployment
- [ ] Write unit tests for core components

### Phase 2: Encryption Implementation (Week 3-4)
**Priority**: High
**Goals**: Add encryption/decryption functionality

Tasks:
- [ ] Implement AES-256-GCM encryption engine
- [ ] Add PBKDF2 key derivation
- [ ] Create streaming encrypt/decrypt readers
- [ ] Implement metadata handling for encrypted objects
- [ ] Add encryption detection and conditional processing
- [ ] Update S3 operations to handle encryption
- [ ] Add encryption/decryption metrics
- [ ] Comprehensive encryption testing

### Phase 3: S3 API Compatibility (Week 5-6)
**Priority**: High
**Goals**: Full S3 API support

Tasks:
- [ ] Implement all major S3 operations (GET, PUT, DELETE, LIST, HEAD)
- [ ] Add multipart upload support with encryption
- [ ] Handle range requests and object versioning
- [ ] Implement proper error translation
- [ ] Add request/response header preservation
- [ ] Support for different S3 providers (AWS, MinIO, Wasabi)
- [ ] Integration testing against real S3 services

### Phase 4: Production Readiness (Week 7-8) ✅
**Priority**: High
**Goals**: Production deployment and monitoring

Tasks:
- [x] Implement comprehensive monitoring and metrics
- [x] Add security hardening and TLS support
- [x] Performance optimization and benchmarking
- [x] Comprehensive documentation
- [x] Security audit and penetration testing (recommendations documented)
- [x] Load testing and scalability validation
- [x] Production deployment manifests

**Status**: ✅ Complete. See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for security audit recommendations.

### Phase 5: Advanced Features (Week 9-10) ✅
**Priority**: Medium
**Goals**: Additional functionality and polish

Tasks:
- [x] Key rotation and management features
- [x] Compression before encryption (already implemented in Phase 2/3)
- [x] Multiple encryption algorithms
- [x] Advanced caching and performance features
- [x] Additional S3 provider support (generic endpoint-based, works with any S3-compatible API)
- [x] Enterprise features (audit logging, compliance)

**Status**: ✅ Complete. Advanced features including key rotation, multiple algorithms, caching, and audit logging are implemented and documented.

**Implemented Features**:
- Key rotation with versioning support
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)
- Advanced in-memory caching with TTL and eviction
- Comprehensive audit logging for compliance

## Security Development Guidelines

### Cryptographic Security
- **Never log sensitive data**: Passwords, keys, or encrypted content
- **Secure key handling**: Zero out keys after use, avoid heap allocation
- **Input validation**: Validate all cryptographic inputs
- **Side-channel resistance**: Use constant-time operations where possible

### Code Security
```go
// Secure password handling
func validatePassword(password string) error {
    if len(password) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    // Additional complexity checks
    return nil
}

// Secure memory handling
func processKey(key []byte) {
    defer func() {
        for i := range key {
            key[i] = 0
        }
    }()
    // Use key...
}
```

### Dependency Security
```bash
# Regular dependency updates
go get -u ./...
go mod tidy

# Vulnerability scanning
govulncheck ./...

# License checking
go-licenses check ./...
```

## Performance Guidelines

### Optimization Principles
- **Memory efficiency**: Stream processing for large objects
- **CPU optimization**: Use hardware-accelerated crypto
- **Concurrent processing**: Leverage goroutines for I/O operations
- **Resource pooling**: Reuse connections and buffers

### Benchmarking
```go
func BenchmarkEncryption(b *testing.B) {
    engine := NewEncryptionEngine("test-password")
    data := make([]byte, 1024*1024) // 1MB test data

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        reader := bytes.NewReader(data)
        encrypted, _ := engine.Encrypt(reader)
        io.Copy(io.Discard, encrypted)
    }
}
```

### Profiling
```bash
# CPU profiling
go test -cpuprofile=cpu.prof ./...

# Memory profiling
go test -memprofile=mem.prof ./...

# View profiles
go tool pprof cpu.prof
```

## Documentation Requirements

### Code Documentation
```go
// Package crypto provides client-side encryption for S3 objects.
//
// It implements AES-256-GCM encryption with PBKDF2 key derivation
// for secure, authenticated encryption of object data.
package crypto

// EncryptionEngine handles encryption and decryption of data streams.
//
// It uses AES-256-GCM for authenticated encryption and supports
// streaming operations for memory efficiency with large objects.
type EncryptionEngine struct {
    // ... fields
}

// NewEncryptionEngine creates a new encryption engine with the given password.
//
// The password is used to derive encryption keys using PBKDF2 with
// 100,000 iterations and a random salt per object.
func NewEncryptionEngine(password string) *EncryptionEngine {
    // ... implementation
}

// Encrypt encrypts the provided data stream.
//
// It returns an encrypted reader that can be used to read the
// encrypted data. The encryption uses AES-256-GCM with a random
// IV and authentication tag for each encryption operation.
func (e *EncryptionEngine) Encrypt(reader io.Reader) (io.Reader, error) {
    // ... implementation
}
```

### API Documentation
- **README.md**: Project overview and quick start
- **API.md**: Detailed API documentation
- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Deployment and configuration guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: System architecture and design decisions

### Inline Comments
- **Exported functions**: Document purpose, parameters, return values
- **Complex logic**: Explain non-obvious algorithms or decisions
- **Security considerations**: Document security-relevant code
- **Error conditions**: Explain when and why errors occur

## Testing Strategy

### Test Categories
- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test component interactions
- **End-to-end tests**: Test complete workflows
- **Performance tests**: Benchmark and load testing
- **Security tests**: Test encryption correctness and vulnerabilities

### Test Data Management
```go
// testdata/ directory structure
testdata/
├── encryption/
│   ├── valid-key.bin
│   ├── corrupted-data.bin
│   └── large-file.bin
├── s3/
│   ├── sample-objects/
│   └── multipart-upload/
└── config/
    └── valid-config.yaml
```

### Mock and Stub Usage
```go
// Mock S3 client for testing
type mockS3Client struct {
    objects map[string][]byte
}

func (m *mockS3Client) GetObject(bucket, key string) ([]byte, error) {
    if data, ok := m.objects[key]; ok {
        return data, nil
    }
    return nil, errors.New("object not found")
}

// Use in tests
func TestGateway_GetObject(t *testing.T) {
    mockClient := &mockS3Client{
        objects: map[string][]byte{
            "test-key": []byte("test data"),
        },
    }

    gateway := NewGateway(mockClient, "password")
    data, err := gateway.GetObject("bucket", "test-key")
    assert.NoError(t, err)
    assert.Equal(t, []byte("test data"), data)
}
```

## Debugging and Troubleshooting

### Logging Best Practices
```go
// Structured logging with context
logger := logrus.WithFields(logrus.Fields{
    "request_id": requestID,
    "bucket": bucket,
    "key": key,
    "operation": "encrypt",
})

// Log different levels appropriately
logger.Debug("Starting encryption process")
logger.Info("Object encrypted successfully")
logger.Warn("Using deprecated encryption algorithm")
logger.Error("Encryption failed", err)

// Include timing information
start := time.Now()
defer func() {
    logger.WithField("duration_ms", time.Since(start).Milliseconds()).Info("Operation completed")
}()
```

#### Access Log Configuration
The gateway supports configurable access logging with multiple formats and sensitive header redaction for security and compliance.

**Configuration Options:**
```yaml
logging:
  access_log_format: "default"  # Options: default, json, clf
  redact_headers:               # Headers to redact in access logs
    - "authorization"
    - "x-amz-security-token"
    - "x-amz-signature"
    - "x-encryption-key"
    - "x-encryption-password"
```

**Access Log Formats:**

1. **Default Format (Structured Fields):**
   ```json
   {
     "method": "GET",
     "path": "/bucket/object",
     "query": "version=1",
     "remote_addr": "192.168.1.100:54321",
     "user_agent": "aws-cli/2.0.0",
     "status": 200,
     "duration_ms": 150,
     "bytes": 1024
   }
   ```

2. **JSON Format (Complete Request Details):**
   ```json
   {
     "timestamp": "2023-11-16T10:30:45Z",
     "method": "PUT",
     "path": "/my-bucket/my-object",
     "query": "",
     "remote_addr": "10.0.0.1:44321",
     "user_agent": "Boto3/1.28.0",
     "status": 200,
     "duration_ms": 245,
     "bytes": 1048576,
     "headers": {
       "content-type": "application/octet-stream",
       "authorization": "[REDACTED]",
       "x-amz-security-token": "[REDACTED]"
     }
   }
   ```

3. **CLF Format (Apache Common Log Format):**
   ```
   192.168.1.100 - - [16/Nov/2023:10:30:45 +0000] "GET /bucket/object HTTP/1.1" 200 1024
   ```

**Environment Variables:**
- `LOGGING_ACCESS_LOG_FORMAT`: Set access log format (`default`, `json`, `clf`)
- `LOGGING_REDACT_HEADERS`: Comma-separated list of headers to redact

**Security Considerations:**
- Sensitive headers (authorization tokens, encryption keys) are automatically redacted
- Redaction is case-insensitive and applies to both request and response headers
- JSON format includes full header information with redaction for compliance auditing
- CLF format follows standard web server logging for compatibility with existing tools

### Debug Mode
```go
// Conditional debug logging
if debugMode {
    logger.WithField("data", hex.EncodeToString(data)).Debug("Raw data")
}

// Debug endpoints for development
func debugHandler(w http.ResponseWriter, r *http.Request) {
    if !isDevelopment {
        http.NotFound(w, r)
        return
    }

    // Return debug information
    info := map[string]interface{}{
        "version": version,
        "uptime":  time.Since(startTime),
        "config":  sanitizedConfig,
    }

    json.NewEncoder(w).Encode(info)
}
```

### Common Debugging Scenarios
- **Encryption failures**: Check password, key derivation, data corruption
- **Performance issues**: Profile CPU/memory usage, check for bottlenecks
- **Network issues**: Verify backend connectivity, check TLS certificates
- **Memory leaks**: Use memory profiling, check for goroutine leaks

## Contributing Guidelines

### Code Contribution Process
1. **Fork** the repository
2. **Create** a feature branch from `main`
3. **Implement** changes with tests
4. **Run** full test suite and linting
5. **Submit** pull request with description
6. **Address** review feedback
7. **Merge** after approval

### Code of Conduct
- Be respectful and inclusive
- Provide constructive feedback
- Focus on code quality and security
- Help newcomers learn and contribute

### Recognition
- Contributors listed in CONTRIBUTORS.md
- Major contributors acknowledged in release notes
- Code review participation valued

This development guide provides a comprehensive foundation for building and maintaining the S3 Encryption Gateway. Follow these guidelines to ensure high-quality, secure, and maintainable code.
