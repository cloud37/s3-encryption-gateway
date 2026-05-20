# Encryption System Design

## Overview

The encryption system provides client-side encryption/decryption for all S3 objects passing through the gateway. It uses authenticated encryption to ensure both confidentiality and integrity of data.

## Encryption Algorithms

- AES-256-GCM (default)
- ChaCha20-Poly1305 (supported in later phases; selectable via configuration)

### AES-256-GCM

### Why AES-256-GCM?
- **Authenticated encryption**: Provides both confidentiality and integrity
- **Industry standard**: Widely adopted and vetted
- **Performance**: Hardware-accelerated on modern CPUs
- **No padding issues**: GCM handles variable-length data efficiently
- **Nonce-based**: No counter state to maintain

### AES-256-GCM Details
- **Key size**: 256 bits (32 bytes)
- **Block size**: 128 bits (16 bytes)
- **Authentication tag**: 128 bits (16 bytes)
- **Nonce/IV size**: 96 bits (12 bytes) - GCM standard

## Key Derivation

### PBKDF2 Key Derivation
```go
func deriveKey(password string, salt []byte) []byte {
    return pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)
}
```

### Parameters
- **Password**: User-provided encryption password
- **Salt**: 32-byte random salt per object
- **Iterations**: 100,000 (balance between security and performance)
- **Hash function**: SHA-256
- **Output length**: 32 bytes (AES-256 key)

### Salt Generation
- **Per-object salt**: Ensures unique key per object
- **Random generation**: Cryptographically secure random bytes
- **Storage**: Stored in object metadata

## Encryption Process

### Data Format
```
Encrypted Object = Salt + IV + Encrypted Data + Authentication Tag
```

### Step-by-Step Encryption (AES-256-GCM)
1. **Generate salt**: 32 bytes of random data
2. **Derive key**: PBKDF2(password, salt, 100000, 32, SHA256)
3. **Generate IV**: 12 bytes of random data
4. **Initialize GCM**: cipher.NewGCM(cipher)
5. **Encrypt**: ciphertext, tag := GCM.Seal(nil, iv, plaintext, nil)
6. **Assemble**: salt + iv + ciphertext + tag
7. **Store metadata**: encryption info in S3 metadata

### Encryption Metadata
```json
{
  "encrypted": true,
  "algorithm": "AES256-GCM",
  "key_salt": "base64-encoded-32-byte-salt",
  "iv": "base64-encoded-12-byte-iv",
  "auth_tag": "base64-encoded-16-byte-tag",
  "original_size": 12345,
  "original_etag": "original-etag-hex",
  "compression": "none"
}
```

## Decryption Process

### Step-by-Step Decryption (AES-256-GCM)
1. **Extract metadata**: Read encryption info from S3 metadata
2. **Verify encryption**: Check "encrypted" flag
3. **Derive key**: Same PBKDF2 process with stored salt
4. **Extract components**: Parse salt, IV, ciphertext, tag
5. **Initialize GCM**: cipher.NewGCM(cipher)
6. **Decrypt**: plaintext, err := GCM.Open(nil, iv, ciphertext, nil)
7. **Verify integrity**: GCM handles authentication automatically
8. **Return data**: Original plaintext

### Error Handling
- **Invalid password**: Decryption will fail with authentication error
- **Corrupted data**: GCM will detect and return error
- **Missing metadata**: Assume unencrypted, pass through
- **Wrong algorithm**: Return error for unsupported algorithms

## Streaming Implementation

### EncryptReader
```go
type EncryptReader struct {
    source  io.Reader
    cipher  cipher.AEAD
    buffer  []byte
    iv      []byte
    salt    []byte
}

func (r *EncryptReader) Read(p []byte) (n int, err error) {
    // Read from source
    // Encrypt in chunks
    // Return encrypted data
}
```

### DecryptReader
```go
type DecryptReader struct {
    source  io.Reader
    cipher  cipher.AEAD
    buffer  []byte
    iv      []byte
}

func (r *DecryptReader) Read(p []byte) (n int, err error) {
    // Read encrypted chunks
    // Decrypt and return
}
```

### Memory Management
- **Chunk size**: 64KB for balanced memory/performance
- **Buffer pooling**: Reuse buffers to reduce allocations
- **Large objects**: Stream processing prevents memory exhaustion
- **Small objects**: Buffer entire object if < 1MB

## Range Request Optimization

### Overview
For chunked encryption, range requests can be optimized by fetching and decrypting only the necessary chunks from S3, rather than downloading the entire encrypted object. This provides significant performance improvements for large objects with small range requests.

### Chunked Encryption Format
Objects are encrypted in fixed-size chunks with independent authentication:
```
Encrypted Object = Chunk_0 + Chunk_1 + ... + Chunk_N
Chunk_i = IV_i + Ciphertext_i + AuthTag_i  (where each chunk is ChunkSize + 16 bytes)
```

### Range Request Processing

#### Step 1: Calculate Required Chunks
Given a plaintext range `[start, end]`, calculate which chunks contain the requested data:

```go
chunkSize = 65536  // 64KB chunks
startChunk = start / chunkSize
endChunk = end / chunkSize
startOffset = start % chunkSize  // Offset within startChunk
endOffset = end % chunkSize      // Offset within endChunk
```

#### Step 2: Calculate Encrypted Byte Range
Convert plaintext chunk range to encrypted byte positions:

```go
encryptedChunkSize = chunkSize + 16  // Include auth tag
encryptedStart = startChunk * encryptedChunkSize
encryptedEnd = (endChunk + 1) * encryptedChunkSize - 1
```

#### Step 3: Optimized S3 Fetch
Request only the necessary encrypted chunks:
```
GET /bucket/key HTTP/1.1
Range: bytes=encryptedStart-encryptedEnd
```

#### Step 4: Range-Aware Decryption
Decrypt only the chunks in the optimized range, extracting the requested plaintext portion.

### Performance Characteristics

#### Benefits
- **Reduced network transfer**: Only fetch required chunks instead of entire object
- **Reduced decryption overhead**: Only decrypt necessary chunks
- **Maintained security**: All accessed chunks have authentication verified

#### Worst-Case Overhead
- **Extra chunk reads**: At most 1 additional chunk if range spans chunk boundaries
- **Memory usage**: Bounded by chunk size (default 64KB + overhead)
- **Authentication verification**: All touched chunks verified (security requirement)

#### Example Performance
For a 1GB object with 16KB range request:
- **Unoptimized**: Transfer 1GB + decrypt 1GB
- **Optimized**: Transfer ~64KB + decrypt ~64KB
- **Improvement**: ~99.99% reduction in network and compute

### Content-Range Header Mapping

Range responses must correctly map plaintext ranges to HTTP Content-Range headers:

```
Content-Range: bytes <start>-<end>/<total>
Content-Length: <actual_response_size>
```

Where:
- `<start>`, `<end>`: Requested plaintext byte range
- `<total>`: Total plaintext object size
- `<actual_response_size>`: Size of returned data (may be less than requested range due to bounds)

### ETag Preservation

Range responses include the original object ETag (not the encrypted ETag) to maintain S3 API compatibility. The ETag is restored from metadata stored during encryption.

### Error Handling

#### Invalid Ranges
- **Out of bounds**: `start < 0` or `end >= totalSize` → 416 Requested Range Not Satisfiable
- **Invalid format**: Malformed range headers → 400 Bad Request
- **Empty ranges**: `start > end` → Error response

#### Decryption Failures
- **Authentication failure**: Corrupted data → 500 Internal Server Error
- **Missing chunks**: Incomplete S3 response → Retry or error
- **Manifest errors**: Invalid chunk metadata → 500 Internal Server Error

### Security Considerations

#### Authentication Verification
All chunks within the requested range have their authentication tags verified, ensuring:
- **Integrity**: Tampered data is detected
- **Confidentiality**: Only authorized decryption succeeds
- **No skip attacks**: Cannot bypass authentication by requesting partial ranges

#### Chunk Alignment
Range optimization maintains chunk boundaries to ensure proper IV derivation and authentication. This prevents attacks that might exploit misaligned decryption.

#### Memory Safety
Range decryption uses streaming with bounded buffers, preventing memory exhaustion attacks on large range requests.

## Key Management

### Password-Based Security
- **User responsibility**: Secure password storage and distribution
- **No key storage**: Keys derived at runtime, never stored
- **Password requirements**: Minimum 12 characters, complexity encouraged

### Future Key Management Service (KMS) Support
- **Interface design**: Pluggable key providers
- **AWS KMS**: Integration with cloud KMS
- **HashiCorp Vault**: Enterprise key management
- **Local KMS**: File-based key storage for development

## Security Considerations

### Cryptographic Security
- **Algorithm security**: AES-256-GCM is quantum-resistant for confidentiality
- **Key derivation**: PBKDF2 provides protection against brute force
- **IV uniqueness**: Random IV per object prevents reuse attacks
- **Authentication**: GCM prevents tampering and ensures integrity

### Operational Security
- **Memory safety**: Keys and plaintext don't persist in memory longer than needed
- **Secure deletion**: Overwrite sensitive data before freeing
- **Audit logging**: Log encryption operations without exposing keys
- **Access controls**: Restrict gateway access to authorized users

### Performance vs Security Trade-offs
- **PBKDF2 iterations**: 100,000 provides good security with acceptable performance
- **Hardware acceleration**: Leverage AES-NI instructions when available
- **Concurrent processing**: Multiple goroutines for parallel encryption

## Metadata Handling

### S3 Metadata Strategy
- **Encryption markers**: Clear indicators of encrypted objects
- **Original preservation**: Store original metadata for restoration
- **Size tracking**: Track original vs encrypted sizes
- **ETag handling**: Store original ETag, provide encrypted ETag to clients

### Metadata Keys
```go
const (
    MetaEncrypted          = "x-amz-meta-encrypted"
    MetaAlgorithm          = "x-amz-meta-encryption-algorithm"
    MetaKeySalt            = "x-amz-meta-encryption-key-salt"
    MetaIV                 = "x-amz-meta-encryption-iv"
    MetaAuthTag            = "x-amz-meta-encryption-auth-tag"
    MetaOriginalSize       = "x-amz-meta-encryption-original-size"
    MetaOriginalETag       = "x-amz-meta-encryption-original-etag"
    MetaCompression        = "x-amz-meta-encryption-compression"
    MetaCompressionEnabled = "x-amz-meta-compression-enabled"
    MetaCompressionAlgorithm = "x-amz-meta-compression-algorithm"
    MetaCompressionOriginalSize = "x-amz-meta-compression-original-size"
)
```

#### Compacted Metadata Keys (Base64URL Strategy)
For providers with strict header limits, metadata keys are compacted using shorter aliases:

```go
// Compacted keys for base64url compaction strategy
"x-amz-meta-e"     // encrypted flag
"x-amz-meta-a"     // algorithm
"x-amz-meta-s"     // key salt
"x-amz-meta-i"     // IV/nonce
"x-amz-meta-os"    // original size
"x-amz-meta-oe"    // original ETag
"x-amz-meta-c"     // chunked format flag
"x-amz-meta-cs"    // chunk size
"x-amz-meta-cc"    // chunk count
"x-amz-meta-m"     // manifest
"x-amz-meta-kv"    // key version
"x-amz-meta-ce"    // compression enabled
"x-amz-meta-ca"    // compression algorithm
"x-amz-meta-cos"   // compression original size
```

### Encrypted Metadata Flow

When a metadata encryption key is configured, the encryption/compression metadata
subset is sealed into a single encrypted blob before storage:

```text
Encrypt Path:
  [Build encMetadata]
      │
      ├── metadataKey == nil ──► [Compact] ──► [Store in S3 headers]
      │
      └── metadataKey != nil ──► [Extract subset]
                                      │
                                      ▼
                              [AES-256-GCM Seal]
                                      │
                                      ▼
                              [Replace with single blob]
                                      │
                                      ▼
                              [Compact] ──► [Store in S3 headers]
```

The decryption path reverses this: after expansion, if `x-amz-meta-enc-metadata`
(or its compacted alias `x-amz-meta-em`) is present, the blob is decrypted and
the recovered keys are merged back into the metadata map.

### Client Response Filtering
- **Hide encryption metadata**: Don't expose internal encryption details
- **Restore original metadata**: Show original Content-Type, ETag, etc.
- **Size reporting**: Report original object size, not encrypted size

## Provider-Specific Metadata Handling

### Provider Profiles
Different S3-compatible providers have varying limits on metadata headers:

| Provider | User Metadata Limit | Total Header Limit | Compaction Strategy |
|----------|-------------------|-------------------|-------------------|
| AWS S3   | 2KB              | 8KB              | base64url         |
| MinIO    | 2KB              | 8KB              | base64url         |
| Wasabi   | 2KB              | 8KB              | base64url         |
| Hetzner  | 2KB              | 8KB              | base64url         |
| Default  | 2KB              | 8KB              | none (backward compatibility) |

### Metadata Compaction Strategies

#### None Strategy (Default)
- Uses full metadata keys as documented above
- No size optimization
- Maintains backward compatibility

#### Base64URL Strategy
- Compacts metadata keys to shorter aliases
- Uses base64url encoding for binary values
- Reduces header size by ~40-50%
- Automatically expands metadata during decryption

### Metadata Size Estimation
Current encryption metadata overhead (uncompacted):
- **16 metadata keys**: ~525 bytes for key names
- **Value data**: ~355 bytes (salts, IVs, sizes, etc.)
- **Total**: ~880 bytes

With compaction:
- **16 metadata keys**: ~225 bytes for compacted key names
- **Value data**: ~355 bytes (same)
- **Total**: ~580 bytes (34% reduction)

### Fallback Storage Strategy
When metadata exceeds provider header limits even after compaction, the system automatically falls back to storing full metadata in the object body:

#### Fallback Format
```
Encrypted Object = AES-GCM([metadata_length][metadata_json][data])
```

Where:
- `metadata_length`: 4-byte big-endian integer
- `metadata_json`: Full metadata as JSON
- `data`: Original data (optionally compressed)

#### Header Metadata (Minimal)
Only essential encryption parameters are stored in headers:
- `x-amz-meta-encrypted: true`
- `x-amz-meta-encryption-fallback: true`
- `x-amz-meta-encryption-algorithm: AES256-GCM`
- `x-amz-meta-encryption-key-salt: <base64>`
- `x-amz-meta-encryption-iv: <base64>`
- `x-amz-meta-encryption-original-size: <size>`
- `x-amz-meta-encryption-original-etag: <etag>`

#### Automatic Detection
The system automatically detects fallback mode during decryption and extracts full metadata from the object body. This is completely transparent to users.

#### Performance Impact
- **Header size**: Minimal (~200 bytes vs ~580 bytes compacted)
- **Network overhead**: Metadata stored in object body adds small overhead
- **Compatibility**: Works with all S3-compatible providers
- **Security**: Full metadata remains encrypted and authenticated

### Configuration
```go
// Enable compaction for AWS S3
engine, err := crypto.NewEngineWithProvider(password, nil, "", nil, "aws")

// Use default (no compaction) for backward compatibility
engine, err := crypto.NewEngine(password)
```

## Compression Integration

### Pre-Encryption Compression (Optional)
- **Configurable**: Can be enabled/disabled based on performance requirements
- **Algorithm**: gzip (most compatible, good compression ratio)
- **When to compress**: Objects > 1KB, compressible content types (text, JSON, XML, etc.)
- **Metadata tracking**: Store compression status and algorithm
- **Decompression**: Automatic on decryption when compression was used
- **Performance trade-off**: ~2-3x slower but saves bandwidth/storage

### Configuration
```go
type CompressionConfig struct {
    Enabled         bool     `yaml:"enabled" env:"COMPRESSION_ENABLED"`
    MinSize         int64    `yaml:"min_size" env:"COMPRESSION_MIN_SIZE"` // Minimum object size to compress
    ContentTypes    []string `yaml:"content_types"` // Content types to compress
    Algorithm       string   `yaml:"algorithm"`     // "gzip", "zstd", etc.
    Level           int      `yaml:"level"`         // Compression level (1-9)
}
```

### Implementation
```go
type CompressionEngine interface {
    Compress(reader io.Reader, contentType string) (io.Reader, *CompressionMetadata, error)
    Decompress(reader io.Reader, metadata *CompressionMetadata) (io.Reader, error)
    ShouldCompress(size int64, contentType string) bool
}

type CompressionMetadata struct {
    Algorithm   string `json:"algorithm"`
    OriginalSize int64  `json:"original_size"`
    CompressedSize int64 `json:"compressed_size"`
}
```

## Performance Optimizations

### Hardware Acceleration
- **AES-NI**: Detect and use hardware AES instructions
- **Parallel processing**: Encrypt/decrypt multiple chunks concurrently
- **Buffer alignment**: Align buffers for optimal crypto performance

### Caching Considerations
- **Key caching**: Cache derived keys for same password/salt combinations
- **Session-based**: Cache keys per encryption session
- **Memory limits**: Bound cache size to prevent memory leaks

### Benchmarking Targets
- **Encryption speed**: > 100 MB/s on modern hardware
- **Decryption speed**: > 100 MB/s on modern hardware
- **Latency overhead**: < 10ms for small objects
- **Memory usage**: < 50MB per concurrent encryption

## Testing and Validation

### Unit Tests
- **Algorithm correctness**: Test vectors from NIST
- **Key derivation**: Validate PBKDF2 implementation
- **Streaming**: Test chunked encryption/decryption
- **Error cases**: Invalid passwords, corrupted data

### Integration Tests
- **Round-trip encryption**: Encrypt ? Decrypt ? Verify identical
- **Large files**: Test with multi-gigabyte objects
- **Concurrent operations**: Test multiple encryptions simultaneously
- **Memory leaks**: Profile memory usage under load

### Security Testing
- **Known plaintext attacks**: Test resistance to cryptanalysis
- **Side-channel analysis**: Timing attack resistance
- **Key leakage**: Ensure keys don't leak in logs or errors
- **Compliance**: Validate against security standards

## Future Extensions

### Additional Algorithms
- **ChaCha20-Poly1305**: Alternative authenticated encryption
- **AES-256-CBC**: Legacy compatibility (with HMAC)
- **Age encryption**: Modern alternative to GPG

### Advanced Features
- **Key rotation**: Support for changing encryption keys
- **Envelope encryption**: Encrypt data keys with master keys
- **Client-side key derivation**: Allow clients to provide derived keys
- **Multi-key encryption**: Support multiple passwords per object

### Enterprise Features
- **KMS integration**: AWS KMS, Azure Key Vault, GCP KMS
- **Key versioning**: Support for key rotation and versioning
- **Access auditing**: Detailed encryption/decryption logs
- **Compliance reporting**: Generate reports for regulatory compliance

## Implementation Roadmap

### Phase 1: Core Encryption
- AES-256-GCM implementation
- PBKDF2 key derivation
- Basic streaming encrypt/decrypt
- Metadata handling

### Phase 2: Performance & Security
- Hardware acceleration detection
- Buffer pooling and optimization
- Comprehensive security testing
- Memory safety improvements

### Phase 3: Advanced Features
- Compression integration
- Multiple algorithm support
- KMS integration interfaces
- Key rotation support
- **Metadata compaction for provider limits (✓ implemented)**
- **Metadata fallback storage strategy (✓ implemented)**

### Phase 4: Enterprise Features
- Audit logging
- Compliance reporting
- Advanced key management
- Performance monitoring
