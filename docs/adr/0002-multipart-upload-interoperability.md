# ADR 0002: Multipart Upload Security Validation and Interoperability

## Status
Accepted

> **Superseded in part by ADR 0009** for buckets with `EncryptMultipartUploads=true`.
> The XML/validation layer described here remains unchanged. Encryption semantics
> for opted-in buckets are now governed by ADR 0009 (v0.6+).

## Context

The S3 Encryption Gateway supports multipart uploads for S3 API compatibility. This ADR documents the XML parsing, request validation, interoperability, and error-translation rules for the multipart control plane.

At the time ADR 0002 was originally written, multipart upload bodies were passed through unencrypted due to architectural limitations. That historical constraint is no longer the full project truth: buckets with `EncryptMultipartUploads=true` now follow ADR 0009, while buckets that opt out continue to use the legacy plaintext path.

Multipart uploads are critical for:
- Large file uploads (>100MB) where single-part uploads may timeout
- Resumable uploads that can recover from network failures
- Parallel upload performance through concurrent part uploads

Multipart uploads introduce security and compatibility challenges regardless of whether the data path is encrypted:
- XML parsing vulnerabilities (XXE, DoS attacks)
- Complex validation requirements for part ordering and ETags
- Provider-specific differences in multipart behavior
- Encryption-mode negotiation between legacy and ADR-0009-backed buckets

## Problem Statement

Multipart uploads create multiple attack vectors and compatibility issues:
- XML external entity (XXE) attacks on CompleteMultipartUpload requests
- Denial of service through malformed or oversized XML payloads
- Authentication bypass through part manipulation
- Compatibility issues across S3 providers (AWS, MinIO, Wasabi, etc.)
- Safe coexistence of legacy plaintext MPU behavior and ADR 0009 encrypted MPU behavior

## Decision

Implement comprehensive security validation for multipart uploads independent of the chosen data path. XML parsing, part validation, backend interoperability, and error translation remain governed by this ADR. Encryption behavior is delegated to ADR 0009 for buckets with `EncryptMultipartUploads=true`; legacy plaintext MPU behavior remains available for buckets that explicitly opt out.

### Key Design Decisions

#### 1. Secure XML Parsing Strategy
- **Decision**: Use Go's standard `encoding/xml` with size limits and validation
- **Rationale**: Prevents XXE attacks, DoS through large documents, and malformed XML
- **Implementation**: 10MB size limit, strict parsing, clear error messages

#### 2. Part Validation Architecture
- **Decision**: Validate parts client-side before forwarding to backend
- **Rationale**: Ensures data integrity and prevents invalid multipart completions
- **Validation**: Part number range (1-10000), ETag format, duplicate detection

#### 3. Provider Abstraction Layer
- **Decision**: Abstract multipart operations through S3Backend interface
- **Rationale**: Enables provider-specific optimizations and compatibility handling
- **Implementation**: Common interface with provider-specific implementations

#### 4. Error Translation Strategy
- **Decision**: Translate backend errors to appropriate S3 error responses
- **Rationale**: Maintains API compatibility and provides meaningful error messages
- **Implementation**: Error code mapping and resource identification

#### 5. Multipart Upload State Management
- **Decision**: Pass-through multipart state management to backend providers
- **Rationale**: Avoids complex state management while leveraging provider reliability
- **Security**: Upload IDs remain opaque, no local state storage

## Implementation Details

### Multipart Upload Encryption Behavior

ADR 0002 no longer defines a single encryption behavior for all multipart uploads.

- **Encrypted MPU path**: Buckets with `EncryptMultipartUploads=true` follow ADR 0009.
- **Legacy plaintext path**: Buckets that explicitly opt out continue to pass multipart bodies through unchanged.

The historical plaintext-only implementation looked like this:

```go
// For multipart uploads, skip encryption to avoid concatenation issues
// Each part would be encrypted individually, but when concatenated on the backend,
// this creates multiple encrypted streams that cannot be decrypted as a single object
var encryptedReader io.Reader = r.Body  // Skip encryption for multipart
```

**Why the legacy plaintext path existed:**
- S3 concatenates multipart upload parts server-side without knowledge of encryption boundaries
- Encrypting each part individually creates multiple encrypted streams
- When concatenated, the result is not a valid encrypted object
- Gateway cannot decrypt such concatenated encrypted streams

ADR 0009 closes that limitation for opted-in buckets by introducing per-upload DEKs, deterministic IV derivation, Valkey-backed upload state, and a finalization manifest.

**Current security implications:**
- Buckets using ADR 0009 store multipart upload data encrypted end-to-end
- Buckets that explicitly opt out retain the legacy plaintext MPU behavior
- `disable_multipart_uploads` remains the fail-closed option for deployments that prefer no MPU path at all

### XML Parsing Security
```go
const maxXMLSize = 10 * 1024 * 1024 // 10MB limit

func parseCompleteMultipartUploadXML(reader io.Reader) (*CompleteMultipartUpload, error) {
    bodyBytes, err := io.ReadAll(io.LimitReader(reader, maxXMLSize))
    if len(bodyBytes) >= maxXMLSize {
        return nil, &S3Error{Code: "InvalidRequest", Message: "Request body too large"}
    }

    decoder := xml.NewDecoder(bytes.NewReader(bodyBytes))
    decoder.CharsetReader = nil // Prevent charset-based attacks

    var req CompleteMultipartUpload
    if err := decoder.Decode(&req); err != nil {
        return nil, &S3Error{Code: "MalformedXML", Message: "Invalid XML format"}
    }

    return &req, nil
}
```

### Part Validation Logic
```go
func validateCompleteMultipartUploadRequest(req *CompleteMultipartUpload) error {
    if len(req.Parts) == 0 {
        return &S3Error{Code: "InvalidArgument", Message: "At least one part required"}
    }

    if len(req.Parts) > 10000 { // AWS limit
        return &S3Error{Code: "InvalidArgument", Message: "Too many parts"}
    }

    // Track seen part numbers for duplicate detection
    seenParts := make(map[int32]bool)
    for _, part := range req.Parts {
        if part.PartNumber < 1 || part.PartNumber > 10000 {
            return &S3Error{Code: "InvalidArgument", Message: "Invalid part number"}
        }
        if seenParts[part.PartNumber] {
            return &S3Error{Code: "InvalidArgument", Message: "Duplicate part number"}
        }
        seenParts[part.PartNumber] = true

        if !isValidETag(part.ETag) {
            return &S3Error{Code: "InvalidArgument", Message: "Invalid ETag format"}
        }
    }

    return nil
}
```

### Provider Interface
```go
type S3Backend interface {
    CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error)
    UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader) (string, error)
    CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error
    AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
    ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error)
}
```

### Error Handling Strategy
```go
func handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request) error {
    // Parse and validate XML
    completeReq, err := parseCompleteMultipartUploadXML(r.Body)
    if err != nil {
        return translateError(err, r.URL.Path)
    }

    // Validate parts
    if err := validateCompleteMultipartUploadRequest(completeReq); err != nil {
        return translateError(err, r.URL.Path)
    }

    // Execute multipart completion
    etag, err := s3Client.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
    if err != nil {
        return translateError(err, bucket, key)
    }

    // Return success response
    return writeCompleteMultipartUploadResponse(w, bucket, key, etag)
}
```

## Security Considerations

### XML Security
- **XXE Prevention**: Disable external entity processing in XML decoder
- **Size Limits**: 10MB maximum XML payload prevents DoS
- **Input Validation**: Strict XML schema validation

### Authentication & Authorization
- **Upload ID Validation**: Opaque upload IDs prevent enumeration attacks
- **Part ETag Verification**: Validates ETag format and prevents manipulation
- **Access Control**: Leverages backend provider's access control

### Data Integrity
- **Part Ordering**: Enforces correct part number sequencing
- **Duplicate Prevention**: Detects and rejects duplicate part numbers
- **Size Validation**: Prevents invalid part size specifications

## Compatibility Strategy

### Provider-Specific Handling
- **AWS S3**: Native multipart support with full feature set
- **MinIO**: Compatible with AWS S3 multipart API
- **Wasabi**: S3-compatible multipart implementation
- **Hetzner**: Multipart support through S3 compatibility layer

### Version Compatibility
- **S3 API Version**: Targets S3 API v2 for broadest compatibility
- **XML Schema**: Follows AWS S3 CompleteMultipartUpload schema
- **Error Codes**: Returns standard S3 error codes for compatibility

## Testing Strategy

### Unit Tests
- XML parsing with malformed inputs
- Part validation edge cases (duplicates, invalid ranges)
- Error translation accuracy

### Integration Tests
- Complete multipart upload lifecycle
- Cross-provider compatibility (AWS, MinIO, Wasabi)
- Error condition handling
- Large multipart uploads (>100 parts)

### Fuzz Testing
- XML payload fuzzing for parser robustness
- Random part number and ETag combinations
- Malformed request testing

### Security Testing
- Large XML payload DoS testing
- XXE attack vector testing
- Authentication bypass attempts

## Performance Considerations

### Memory Management
- **Streaming Parsing**: XML parsed without full buffer allocation
- **Size Limits**: Prevents memory exhaustion attacks
- **Validation Efficiency**: Fast validation without repeated parsing

### Network Efficiency
- **Direct Forwarding**: Multipart operations forwarded directly to backend
- **Minimal Buffering**: Parts streamed through without local storage
- **Concurrent Processing**: Multiple parts can be processed simultaneously

## Error Handling

### Client Errors (4xx)
- `InvalidRequest`: Malformed requests or invalid parameters
- `InvalidArgument`: Invalid part numbers, ETags, or duplicate parts
- `MalformedXML`: Invalid XML structure or content
- `EntityTooLarge`: XML payload exceeds size limits

### Server Errors (5xx)
- `InternalError`: Unexpected server errors during processing
- `ServiceUnavailable`: Backend provider unavailable
- `SlowDown`: Rate limiting or throttling

### Error Translation
```go
func translateError(err error, resource string) *S3Error {
    if s3Err, ok := err.(*S3Error); ok {
        s3Err.Resource = resource
        return s3Err
    }

    // Translate backend errors to S3 equivalents
    switch err.(type) {
    case *awserr.Error:
        return translateAWSError(err, resource)
    default:
        return &S3Error{
            Code:      "InternalError",
            Message:   "An internal error occurred",
            Resource:  resource,
            HTTPStatus: http.StatusInternalServerError,
        }
    }
}
```

## Alternatives Considered

### Alternative 1: Encrypt Multipart Parts Individually
- **Pros**: Would encrypt all data including multipart uploads
- **Cons**: S3 concatenates parts server-side, creating invalid encrypted streams that cannot be decrypted
- **Decision**: Rejected due to fundamental incompatibility with S3 multipart concatenation

### Alternative 2: Client-side Multipart Reassembly
- **Pros**: Could encrypt complete objects before multipart upload
- **Cons**: Requires buffering entire objects in memory/network, defeats multipart purpose
- **Decision**: Rejected due to memory and performance implications

### Alternative 3: Disable Multipart Uploads Entirely
- **Pros**: Simpler security model, all data guaranteed encrypted
- **Cons**: Breaks compatibility for large uploads, poor user experience
- **Decision**: Rejected due to S3 API compatibility requirements, but provided as optional security feature

### Alternative 4: Custom Binary Protocol
- **Pros**: Potentially more secure, smaller payload size
- **Cons**: Not S3 compatible, requires client changes
- **Decision**: Rejected due to S3 API compatibility requirements

## Migration Strategy

### Backward Compatibility
- Multipart support added without breaking existing functionality
- Single-part uploads continue to work unchanged
- Graceful degradation for unsupported multipart operations

### Feature Flags
- Multipart uploads can be disabled via configuration
- Allows gradual rollout and troubleshooting
- Provides fallback for security-sensitive deployments

## Future Considerations

### Enhanced Security
- Request signing validation for multipart operations
- Rate limiting per upload ID
- Upload size and duration limits

### Performance Optimizations
- Parallel part processing
- Memory-efficient XML parsing
- Connection pooling for multipart operations

### Advanced Features
- **Multipart copy operations** – See ADR 0006 for UploadPartCopy implementation and source-format dispatch strategies (V0.6-S3-1)
- Progress tracking and resumability
- Client-side encryption for multipart uploads
- **Encrypted multipart destinations** – Future proposal would introduce chunked-MPU with finalization manifest; documented in ADR 0006 §Future Considerations

## References

- [AWS S3 Multipart Upload API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html)
- [XML External Entity (XXE) Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [S3 API Compatibility Guidelines](https://docs.min.io/docs/minio-server-reference-guide.html)
