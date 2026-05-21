package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/kenchrcum/s3-encryption-gateway/internal/debug"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Key derivation parameters — per-object iteration count is now configurable
	// via engine.pbkdf2Iterations; the legacy constant is kept in kdf.go as
	// LegacyPBKDF2Iterations for decrypt fallback.
	aesKeySize = 32 // 256 bits
	saltSize   = 32 // 256 bits
	nonceSize  = 12 // 96 bits for GCM
	tagSize    = 16 // 128 bits authentication tag

	// Metadata keys for encryption information
	MetaEncrypted               = "x-amz-meta-encrypted"
	MetaAlgorithm               = "x-amz-meta-encryption-algorithm"
	MetaKeySalt                 = "x-amz-meta-encryption-key-salt"
	MetaIV                      = "x-amz-meta-encryption-iv"
	MetaAuthTag                 = "x-amz-meta-encryption-auth-tag"
	MetaOriginalSize            = "x-amz-meta-encryption-original-size"
	MetaOriginalETag            = "x-amz-meta-encryption-original-etag"
	MetaCompression             = "x-amz-meta-encryption-compression"
	MetaCompressionEnabled      = "x-amz-meta-compression-enabled"
	MetaCompressionAlgorithm    = "x-amz-meta-compression-algorithm"
	MetaCompressionOriginalSize = "x-amz-meta-compression-original-size"
	MetaWrappedKeyCiphertext    = "x-amz-meta-encryption-wrapped-key"
	MetaKMSKeyID                = "x-amz-meta-encryption-kms-id"
	MetaKMSProvider             = "x-amz-meta-encryption-kms-provider"
	MetaContentType             = "x-amz-meta-encryption-content-type"
	// MetaKDFParams stores the KDF algorithm and parameters used to derive the
	// per-object encryption key. Format: "pbkdf2-sha256:<iterations>" or
	// "argon2id:<time>:<memory_kib>:<threads>".
	// Absent on objects written before V1.0-SEC-H03.
	MetaKDFParams = "x-amz-meta-encryption-kdf-params"

	// Metadata encryption blob (V1.0-CRYPTO-3).
	// MetaEncryptedMetadata is the full key for the encrypted metadata blob.
	// MetaEncryptedMetadataCompact is the compacted alias.
	MetaEncryptedMetadata        = "x-amz-meta-enc-metadata"
	MetaEncryptedMetadataCompact = "x-amz-meta-em"

	// Fallback metadata storage keys
	MetaFallbackMode    = "x-amz-meta-encryption-fallback"
	MetaFallbackPointer = "x-amz-meta-encryption-fallback-ptr"
	// MetaFallbackVersion distinguishes on-disk formats for the metadata fallback path.
	// "1" (or absent): legacy format — chunked ciphertext wrapped in a second outer AEAD Seal.
	// "2": streaming format — raw [4-byte-BE metadata_length][metadata_json][chunked_stream],
	//      no outer AEAD wrapper (per-chunk AEAD from the chunked layer is sufficient).
	MetaFallbackVersion = "x-amz-meta-encryption-fallback-version"

	// Legacy marker for objects encrypted before AAD was introduced.
	// The no-AAD fallback in Decrypt is only permitted when this flag is "true".
	// Deprecated: remove no-AAD fallback path in v3.0 (same policy as XOR-IV and fallback-v1).
	MetaLegacyNoAAD = "x-amz-meta-enc-legacy-no-aad"
)

// EncryptionEngine provides encryption and decryption functionality.
type EncryptionEngine interface {
	// Encrypt encrypts data from the reader and returns an encrypted reader
	// along with encryption metadata.
	Encrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)

	// Decrypt decrypts data from the reader using the provided metadata
	// and returns a decrypted reader along with updated metadata.
	Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error)

	// DecryptRange decrypts a specific byte range from the reader, returning plaintext
	// bounded by the requested plaintext range [plaintextStart, plaintextEnd].
	// Efficiently handles chunked sources by seeking within the encrypted stream.
	DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)

	// IsEncrypted checks if the metadata indicates the object is encrypted.
	IsEncrypted(metadata map[string]string) bool

	// PreferredAlgorithm returns the preferred encryption algorithm for new objects.
	PreferredAlgorithm() string
}

// engine implements the EncryptionEngine interface.
// Argon2idConfig holds operator-tunable argon2id KDF parameters.
//
// Recommended production values (OWASP 2024):
//   Time    = 2
//   Memory  = 19456  (19 MiB)
//   Threads = 1
//
// These are the minimums; operators may raise them for higher attack cost.
type Argon2idConfig struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

type engine struct {
	password         []byte
	pbkdf2Iterations int // configurable, default DefaultPBKDF2Iterations
	kdfAlgorithm     KDFAlgorithm // selected KDF for new objects, default KDFAlgPBKDF2SHA256
	argon2idParams   Argon2idConfig
	compressionEngine   CompressionEngine
	preferredAlgorithm  string
	supportedAlgorithms []string
	// Chunked encryption settings
	chunkedMode bool // Enable chunked/streaming encryption mode
	chunkSize   int  // Size of each encryption chunk (default: DefaultChunkSize)
	// Provider and compaction settings
	providerProfile *ProviderProfile
	compactor       *MetadataCompactor
	// Buffer pool for reducing allocations
	bufferPool *BufferPool
	// Tracing
	tracer trace.Tracer
	// External key manager (optional)
	kmsManager KeyManager
	// Rotation state machine for drain-and-cutover tracking
	rotationState *RotationState
	// Metadata encryption key (V1.0-CRYPTO-3).
	// metadataKey is the 32-byte AES-256 key for encrypting metadata blobs.
	// metadataKeyWrapped is set when a KeyManager wraps the key at startup.
	metadataKey        []byte
	metadataKeyWrapped *KeyEnvelope
	// V1.0-OBS-1 G8: optional observer for encrypted object size distribution.
	observeEncryptedObjectBytes func(n int64)
}

// NewEngine creates a new encryption engine with the given password.
//
// The password is used to derive encryption keys using PBKDF2 with
// the default iteration count (600,000) and a random salt per object.
func NewEngine(password []byte) (EncryptionEngine, error) {
	return NewEngineWithCompression(password, nil)
}

// NewEngineWithCompression creates a new encryption engine with compression support.
func NewEngineWithCompression(password []byte, compressionEngine CompressionEngine) (EncryptionEngine, error) {
	return NewEngineWithOptions(password, compressionEngine, "", nil)
}

// NewEngineWithOptions creates a new encryption engine with full options.
func NewEngineWithOptions(password []byte, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string) (EncryptionEngine, error) {
	return NewEngineWithProvider(password, compressionEngine, preferredAlgorithm, supportedAlgorithms, "default")
}

// NewEngineWithProvider creates a new encryption engine with provider-specific settings.
func NewEngineWithProvider(password []byte, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string, provider string) (EncryptionEngine, error) {
	return NewEngineWithChunkingAndProvider(password, compressionEngine, preferredAlgorithm, supportedAlgorithms, false, DefaultChunkSize, provider, DefaultPBKDF2Iterations)
}

// NewEngineWithChunking creates a new encryption engine with chunked mode support.
func NewEngineWithChunking(password []byte, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string, chunkedMode bool, chunkSize int) (EncryptionEngine, error) {
	return NewEngineWithChunkingAndProvider(password, compressionEngine, preferredAlgorithm, supportedAlgorithms, chunkedMode, chunkSize, "default", DefaultPBKDF2Iterations)
}

// NewEngineWithChunkingAndProvider creates a new encryption engine with chunked mode and provider support.
func NewEngineWithChunkingAndProvider(password []byte, compressionEngine CompressionEngine, preferredAlgorithm string, supportedAlgorithms []string, chunkedMode bool, chunkSize int, provider string, pbkdf2Iterations int) (EncryptionEngine, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("encryption password cannot be empty")
	}

	if len(password) < 12 {
		return nil, fmt.Errorf("encryption password must be at least 12 characters")
	}

	// Default algorithm configuration
	if preferredAlgorithm == "" {
		preferredAlgorithm = AlgorithmAES256GCM
	}

	if len(supportedAlgorithms) == 0 {
		supportedAlgorithms = []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305}
	}

	// Validate preferred algorithm
	if !isAlgorithmSupported(preferredAlgorithm, supportedAlgorithms) {
		return nil, fmt.Errorf("preferred algorithm %s is not in supported algorithms list", preferredAlgorithm)
	}

	// Validate and set chunk size
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	// Get provider profile and create compactor
	profile := GetProviderProfile(provider)
	compactor := NewMetadataCompactor(profile)

	// Log hardware acceleration info
	if HasAESHardwareSupport() {
		// Hardware acceleration is available (Go's crypto automatically uses it)
		// We could log this for monitoring purposes
	}

	// Copy password into a []byte slice so we can zeroize it on Close().
	// The caller's string is not modified.
	passwordBytes := make([]byte, len(password))
	copy(passwordBytes, password)

	e := &engine{
		password:            passwordBytes,
		pbkdf2Iterations:    pbkdf2Iterations,
		kdfAlgorithm:        KDFAlgPBKDF2SHA256,
		argon2idParams: Argon2idConfig{
			Time:    2,
			Memory:  19456,
			Threads: 1,
		},
		compressionEngine:   compressionEngine,
		preferredAlgorithm:  preferredAlgorithm,
		supportedAlgorithms: supportedAlgorithms,
		chunkedMode:         chunkedMode,
		chunkSize:           chunkSize,
		providerProfile:     profile,
		compactor:           compactor,
		bufferPool:          GetGlobalBufferPool(),
		tracer:              otel.Tracer("s3-encryption-gateway.crypto"),
	}
	e.maybeWireObserver()
	return e, nil
}

// SetKeyManager wires an external KeyManager into the engine for envelope encryption.
//
// Deprecated: Pass [WithKeyManager] to [NewEngineWithOpts] instead. This function
// will be removed in a future release.
func SetKeyManager(enc EncryptionEngine, manager KeyManager) {
	if e, ok := enc.(*engine); ok {
		e.kmsManager = manager
	}
}

// GetKeyManager returns the engine's configured KeyManager, or nil if no
// external KMS is configured. Used by the admin rotation handler.
func GetKeyManager(enc EncryptionEngine) KeyManager {
	if e, ok := enc.(*engine); ok {
		return e.kmsManager
	}
	return nil
}

// observeEncryptedObjectBytes is a package-level function callback for observing
// encrypted object sizes. Using a callback avoids a circular import between
// internal/crypto and internal/metrics.
var observeEncryptedObjectBytes func(n int64)

// SetEncryptedObjectSizeObserver sets the observer function for encrypted object
// size distribution (V1.0-OBS-1 G8). It is safe to call with a nil function
// — the engine will skip the call. Using a function callback avoids a
// circular import between internal/crypto and internal/metrics.
func SetEncryptedObjectSizeObserver(fn func(n int64)) {
	observeEncryptedObjectBytes = fn
}

// maybeWireObserver captures the current global observer function into this
// engine instance. New engines created before SetEncryptedObjectSizeObserver is
// called will have a nil observer; main.go wires it after engine construction.
func (e *engine) maybeWireObserver() {
	e.observeEncryptedObjectBytes = observeEncryptedObjectBytes
}

// GetRotationState returns the engine's rotation state machine. If no state
// has been set, it initialises an idle one.
func GetRotationState(enc EncryptionEngine) *RotationState {
	if e, ok := enc.(*engine); ok {
		if e.rotationState == nil {
			e.rotationState = NewRotationState()
		}
		return e.rotationState
	}
	return NewRotationState()
}

// deriveKeyWithParams derives a key using the given KDFParams.
func (e *engine) deriveKeyWithParams(salt []byte, params KDFParams) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", saltSize, len(salt))
	}

	switch params.Algorithm {
	case KDFAlgPBKDF2SHA256:
		key, err := pbkdf2.Key(sha256.New, string(e.password), salt, params.Iterations, aesKeySize)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key with PBKDF2: %w", err)
		}
		return key, nil
	case KDFAlgArgon2id:
		return deriveKeyArgon2id(e.password, salt, params)
	default:
		return nil, fmt.Errorf("unsupported KDF algorithm: %s", params.Algorithm)
	}
}

// deriveKey derives a key for new objects using the engine's configured algorithm.
func (e *engine) deriveKey(salt []byte) ([]byte, error) {
	switch e.kdfAlgorithm {
	case KDFAlgArgon2id:
		return e.deriveKeyWithParams(salt, KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      e.argon2idParams.Time,
			Memory:    e.argon2idParams.Memory,
			Threads:   e.argon2idParams.Threads,
		})
	default:
		return e.deriveKeyWithParams(salt, DefaultKDFParams(e.pbkdf2Iterations))
	}
}

// defaultKDFParams returns the KDFParams for newly written objects based on the
// engine's configured algorithm.
func (e *engine) defaultKDFParams() KDFParams {
	switch e.kdfAlgorithm {
	case KDFAlgArgon2id:
		return KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      e.argon2idParams.Time,
			Memory:    e.argon2idParams.Memory,
			Threads:   e.argon2idParams.Threads,
		}
	default:
		return DefaultKDFParams(e.pbkdf2Iterations)
	}
}

// generateSalt generates a cryptographically secure random salt.
func (e *engine) generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// generateNonce generates a cryptographically secure random nonce/IV.
func (e *engine) PreferredAlgorithm() string {
	return e.preferredAlgorithm
}

func (e *engine) generateNonce() ([]byte, error) {
	return e.generateNonceForAlgorithm(e.preferredAlgorithm)
}

// generateNonceForAlgorithm generates a nonce with the correct size for the algorithm.
func (e *engine) generateNonceForAlgorithm(algorithm string) ([]byte, error) {
	nonceSize, err := getNonceSize(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce size for algorithm %s: %w", algorithm, err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// createCipher creates an AES cipher for the given key.
func (e *engine) createCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm, nil
}

// generateDataKey generates a random data key of the specified size.
// It is assigned to a variable so tests can temporarily replace it to
// simulate key-size mismatches.
var generateDataKey = func(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data from the reader and returns an encrypted reader
// along with encryption metadata.
func (e *engine) Encrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	ctx, span := e.tracer.Start(ctx, "Crypto.Encrypt",
		trace.WithAttributes(
			attribute.String("crypto.algorithm", e.preferredAlgorithm),
			attribute.Bool("crypto.chunked", e.chunkedMode),
		),
	)
	defer span.End()

	// If chunked mode is enabled, use streaming chunked encryption
	if e.chunkedMode {
		encryptedReader, meta, err := e.encryptChunked(ctx, reader, metadata)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, nil, err
		}
		span.SetStatus(codes.Ok, "")
		return encryptedReader, meta, nil
	}

	// Legacy buffered mode for backward compatibility
	// Read the plaintext first to get size and content type (needed for compression decision)
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, fmt.Errorf("failed to read plaintext: %w", err)
	}
	originalSize := int64(len(plaintext))
	// V1.0-OBS-1 G8: observe plaintext object size distribution.
	if e.observeEncryptedObjectBytes != nil {
		e.observeEncryptedObjectBytes(originalSize)
	}

	// Extract content type from metadata
	contentType := ""
	if metadata != nil {
		contentType = metadata["Content-Type"]
	}

	// Compute original ETag from original (uncompressed) data
	// This must be done before compression potentially changes the data
	originalETag := computeETag(plaintext)

	// V0.6-PERF-1 Phase F: Apply compression if enabled and applicable.
	// The intermediate bytes.NewReader(compressedData) double-buffer is
	// eliminated: Compress (Phase E) now returns a streaming pipe reader, so
	// we can read compressed bytes directly into the gcm.Seal call below via a
	// single io.ReadAll. For legacy single-AEAD mode, gcm.Seal requires a
	// []byte, so we must buffer the compressed output — but the plaintext
	// buffer is no longer replicated.
	var toEncryptReader io.Reader = bytes.NewReader(plaintext)
	compressionMetadata := make(map[string]string)
	if e.compressionEngine != nil {
		compressedReader, compMeta, err := e.compressionEngine.Compress(bytes.NewReader(plaintext), contentType, originalSize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compress data: %w", err)
		}
		if compMeta != nil {
			// Compression was applied; compressedReader is now a streaming pipe.
			// Set toEncryptReader to the compressed stream; io.ReadAll below will
			// drain it in one pass — no intermediate bytes.NewReader wrapper needed.
			compressionMetadata = compMeta
			toEncryptReader = compressedReader
		}
		// If compression wasn't applied, compMeta will be nil and we continue with original
	}

	// Determine algorithm to use (preferred algorithm for new encryptions)
	algorithm := e.preferredAlgorithm

	// Generate salt and nonce for this encryption
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce, err := e.generateNonceForAlgorithm(algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var (
		key      []byte
		envelope *KeyEnvelope
	)

	if e.kmsManager != nil {
		key, err = generateDataKey(keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
		}
		if e.rotationState != nil {
			e.rotationState.BeginWrap()
		}
		envelope, err = e.kmsManager.WrapKey(ctx, key, metadata)
		if e.rotationState != nil {
			e.rotationState.EndWrap()
		}
		if err != nil {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("failed to wrap data key: %w", err)
		}
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		// generateDataKey always returns exactly keySize bytes;
		// the following check is a defensive assertion.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: generateDataKey returned unexpected key size %d (want %d)", len(key), keySize)
		}
	} else {
		key, err = e.deriveKey(salt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	// Prepare encryption metadata early so we can detect fallback before
	// allocating the ciphertext buffer.  This avoids encrypting the payload
	// twice when the metadata must be stored inside the object body.
	encMetadata := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata {
			encMetadata[k] = v
		}
	}
	if compressionMetadata != nil {
		for k, v := range compressionMetadata {
			encMetadata[k] = v
		}
	}
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaAlgorithm] = algorithm
	encMetadata[MetaKeySalt] = encodeBase64(salt)
	encMetadata[MetaIV] = encodeBase64(nonce)
	encMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	encMetadata[MetaOriginalETag] = originalETag
	encMetadata[MetaKDFParams] = FormatKDFParams(e.defaultKDFParams())
	if contentType != "" {
		encMetadata[MetaContentType] = contentType
	}
	if envelope != nil {
		encMetadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		if envelope.KeyID != "" {
			encMetadata[MetaKMSKeyID] = envelope.KeyID
		}
		if envelope.Provider != "" {
			encMetadata[MetaKMSProvider] = envelope.Provider
		}
		encMetadata[MetaWrappedKeyCiphertext] = encodeBase64(envelope.Ciphertext)
	} else if kv, ok := metadata[MetaKeyVersion]; ok && kv != "" {
		encMetadata[MetaKeyVersion] = kv
	}

	// V1.0-CRYPTO-3: encrypt metadata blob if metadata key is configured.
	// This replaces all individual encryption/compression metadata keys with
	// a single AES-256-GCM sealed blob under MetaEncryptedMetadata.
	if e.metadataKey != nil {
		blob, err := e.encryptMetadata(encMetadata)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, nil, fmt.Errorf("encrypt metadata: %w", err)
		}
		// Remove all encryption/compression keys from the cleartext map.
		for k := range encMetadata {
			if IsEncryptionMetadata(k) || IsCompressionMetadata(k) {
				delete(encMetadata, k)
			}
		}
		// MetaEncrypted (x-amz-meta-encrypted) MUST remain outside the blob
		// so that IsEncrypted works even without the metadata key (§2.6).
		encMetadata[MetaEncrypted] = "true"
		encMetadata[MetaEncryptedMetadata] = blob
	}

	// Check if we need fallback metadata storage before encrypting.
	if e.needsMetadataFallback(encMetadata) {
		return e.encryptWithMetadataFallback(plaintext, encMetadata, contentType, originalSize, originalETag)
	}

	// Create cipher using selected algorithm
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	gcm := aeadCipher.(cipher.AEAD) // For backward compatibility with existing code

	// Read data to encrypt (may be compressed). Single allocation: drains the
	// streaming compression pipe (or the original plaintext bytes.Reader) directly.
	dataToEncrypt, err := io.ReadAll(toEncryptReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data for encryption: %w", err)
	}

	// Build AAD to bind critical metadata
	aadMeta := map[string]string{
		"Content-Type":   contentType,
		MetaKeyVersion:   metadata[MetaKeyVersion],
		MetaOriginalSize: fmt.Sprintf("%d", originalSize),
	}
	aad := buildAAD(algorithm, salt, nonce, aadMeta)
	// Debug: log AAD for troubleshooting (no raw crypto values logged).
	if debug.Enabled() {
		slog.Debug("encrypt AAD built",
			"algorithm", algorithm,
			"salt_len", len(salt),
			"iv_len", len(nonce),
			"aad_len", len(aad),
			"content_type", contentType,
			"key_version", aadMeta[MetaKeyVersion],
			"original_size", aadMeta[MetaOriginalSize],
		)
	}
	// Encrypt the data using AEAD with AAD
	ciphertext := gcm.Seal(nil, nonce, dataToEncrypt, aad)

	// Debug: log encryption info for troubleshooting (no raw crypto material logged).
	if debug.Enabled() && len(ciphertext) > 0 {
		slog.Debug("encrypt complete",
			"ciphertext_len", len(ciphertext),
			"salt_len", len(salt),
			"iv_len", len(nonce),
		)
	}

	// Create encrypted reader from ciphertext
	encryptedReader := bytes.NewReader(ciphertext)

	// Compact metadata according to provider profile
	compactedMetadata, err := e.compactor.CompactMetadata(encMetadata)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, fmt.Errorf("failed to compact metadata: %w", err)
	}

	span.SetStatus(codes.Ok, "")
	return encryptedReader, compactedMetadata, nil
}

// Decrypt decrypts data from the reader using the provided metadata
// and returns a decrypted reader along with updated metadata.
func (e *engine) Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	ctx, span := e.tracer.Start(ctx, "Crypto.Decrypt",
		trace.WithAttributes(
			attribute.Bool("crypto.chunked", e.IsEncrypted(metadata) && isChunkedFormat(metadata)),
		),
	)
	defer span.End()
	if !e.IsEncrypted(metadata) {
		// Not encrypted, return as-is
		return reader, metadata, nil
	}

	// Check if this is fallback mode (metadata stored in object body)
	if e.isFallbackMode(metadata) {
		return e.decryptWithMetadataFallback(ctx, reader, metadata)
	}

	// Expand compacted metadata first
	expandedMetadata, err := e.compactor.ExpandMetadata(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to expand metadata: %w", err)
	}

	// V1.0-CRYPTO-3: decrypt encrypted metadata blob if metadata key is configured.
	if e.metadataKey != nil {
		blobKey := MetaEncryptedMetadata
		if _, ok := expandedMetadata[MetaEncryptedMetadataCompact]; ok {
			blobKey = MetaEncryptedMetadataCompact
		}
		if blob, ok := expandedMetadata[blobKey]; ok && blob != "" {
			decryptedMeta, err := e.decryptMetadata(blob)
			if err != nil {
				return nil, nil, fmt.Errorf("decrypt metadata: %w", err)
			}
			for k, v := range decryptedMeta {
				expandedMetadata[k] = v
			}
			delete(expandedMetadata, blobKey)
		}
	}

	// Check if this is chunked format
	if isChunkedFormat(expandedMetadata) {
		return e.decryptChunked(ctx, reader, expandedMetadata)
	}

	// Legacy buffered mode for backward compatibility

	salt, err := decodeBase64(expandedMetadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	iv, err := decodeBase64(expandedMetadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	algorithm := expandedMetadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s (not in supported list)", algorithm)
	}

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var key []byte

	if e.kmsManager != nil && expandedMetadata[MetaWrappedKeyCiphertext] != "" {
		wrappedKeyB64 := expandedMetadata[MetaWrappedKeyCiphertext]
		ciphertext, err := decodeBase64(wrappedKeyB64)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode wrapped data key (length=%d): %w", len(wrappedKeyB64), err)
		}
		env := &KeyEnvelope{
			KeyID:      expandedMetadata[MetaKMSKeyID],
			KeyVersion: parseKeyVersion(expandedMetadata[MetaKeyVersion]),
			Provider:   expandedMetadata[MetaKMSProvider],
			Ciphertext: ciphertext,
		}
		// Validate that we have the required fields
		if env.KeyID == "" {
			return nil, nil, fmt.Errorf("failed to unwrap data key: KMS key ID is missing from metadata")
		}
		if len(env.Ciphertext) == 0 {
			return nil, nil, fmt.Errorf("failed to unwrap data key: wrapped key ciphertext is empty")
		}
		// Validate wrapped key size. The acceptable range depends on the KEK algorithm:
		//   - AES key-wrap (RFC 3394):  plaintext + 8 bytes (e.g. 40 bytes for a 32-byte DEK)
		//   - RSA-OAEP (2048-bit key):  256 bytes
		//   - RSA-OAEP (4096-bit key):  512 bytes
		//   - RSA-OAEP (8192-bit key):  1024 bytes
		// The upper bound of 1024 covers RSA keys up to 8192 bits; anything larger
		// is rejected as likely corrupted metadata. The lower bound of 32 ensures
		// we always have at least enough bytes to attempt an AES or RSA unwrap.
		if len(env.Ciphertext) < 32 || len(env.Ciphertext) > 1024 {
			return nil, nil, fmt.Errorf("failed to unwrap data key: wrapped key ciphertext has unexpected size %d bytes (expected 32-1024 bytes)", len(env.Ciphertext))
		}
		key, err = e.kmsManager.UnwrapKey(ctx, env, expandedMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unwrap data key (keyID=%s, provider=%s, keyVersion=%d, wrappedKeySize=%d): %w", env.KeyID, env.Provider, env.KeyVersion, len(env.Ciphertext), err)
		}
		// Validate unwrapped key size
		if len(key) != keySize {
			return nil, nil, fmt.Errorf("failed to unwrap data key: KMS returned key of size %d, expected %d", len(key), keySize)
		}
	} else {
		// Read KDF params; absent -> legacy 100k PBKDF2.
		kdfParams, err := ParseKDFParams(expandedMetadata[MetaKDFParams])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse KDF params: %w", err)
		}
		key, err = e.deriveKeyWithParams(salt, kdfParams)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	gcm := aeadCipher.(cipher.AEAD)

	// Read all encrypted data (current implementation is buffered)
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}
	// Debug: log decryption parameters (no raw crypto values logged).
	if debug.Enabled() {
		slog.Debug("decrypt starting",
			"ciphertext_len", len(ciphertext),
			"algorithm", algorithm,
			"has_salt", expandedMetadata[MetaKeySalt] != "",
			"has_iv", expandedMetadata[MetaIV] != "",
		)
	}

	// Build AAD from expanded metadata.
	// We MUST use only MetaContentType (the value stored at encryption time).
	// Do NOT fall back to expandedMetadata["Content-Type"]: the S3 backend
	// may inject a non-empty Content-Type (e.g. "application/octet-stream")
	// that was never included in the AAD during encryption, causing AEAD
	// authentication to fail.  If MetaContentType is absent, the object was
	// encrypted with contentType="" and we reconstruct that exact AAD.
	contentType := expandedMetadata[MetaContentType]
	aadMeta := map[string]string{
		MetaKeyVersion:   expandedMetadata[MetaKeyVersion],
		MetaOriginalSize: expandedMetadata[MetaOriginalSize],
		"Content-Type":   contentType,
	}
	aad := buildAAD(algorithm, salt, iv, aadMeta)
	// Debug: log AAD for troubleshooting (no raw crypto values logged).
	if debug.Enabled() {
		slog.Debug("decrypt AAD built",
			"algorithm", algorithm,
			"salt_len", len(salt),
			"iv_len", len(iv),
			"aad_len", len(aad),
			"content_type", aadMeta["Content-Type"],
			"key_version", aadMeta[MetaKeyVersion],
			"original_size", aadMeta[MetaOriginalSize],
		)
	}

	// Attempt decrypt with current key and AAD (new length-prefixed format)
	plaintext, openErr := gcm.Open(nil, iv, ciphertext, aad)
	if openErr != nil {
		// Backward compatibility: try legacy pipe-delimited AAD format
		// for objects created before V1.0-SEC-H01.
		aadLegacy := buildAADLegacy(algorithm, salt, iv, aadMeta)
		if pt, err2 := gcm.Open(nil, iv, ciphertext, aadLegacy); err2 == nil {
			plaintext = pt
			openErr = nil
		}
	}
	if openErr != nil {
		// Backward compatibility: try without AAD only for explicitly
		// marked legacy objects. This prevents an attacker with backend
		// write access from bypassing the AAD integrity check by
		// tampering with metadata.
		if expandedMetadata[MetaLegacyNoAAD] == "true" {
			if pt, err2 := gcm.Open(nil, iv, ciphertext, nil); err2 == nil {
				plaintext = pt
				openErr = nil
			}
		}
	}

	if openErr != nil {
		return nil, nil, fmt.Errorf("failed to decrypt data (algorithm=%s, keySize=%d, ivSize=%d, ciphertextSize=%d): %w", algorithm, len(key), len(iv), len(ciphertext), openErr)
	}

	// V0.6-PERF-1 Phase F: Apply decompression if compression was used.
	// Decompress (Phase E) now returns a streaming gzip.Reader wrapping the
	// plaintext directly — no intermediate ReadAll → bytes.NewReader needed.
	// For non-compressed objects, plaintext is used directly.
	var finalReader io.Reader = bytes.NewReader(plaintext)
	if e.compressionEngine != nil {
		decompressedReader, err := e.compressionEngine.Decompress(bytes.NewReader(plaintext), expandedMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress data: %w", err)
		}
		finalReader = decompressedReader
		// V1.0-SEC-M05: bound decompressed output to prevent decompression bombs
		if originalSizeStr, ok := expandedMetadata[MetaCompressionOriginalSize]; ok {
			if originalSize, err := strconv.ParseInt(originalSizeStr, 10, 64); err == nil && originalSize > 0 {
				limit := originalSize + 65536 // 64 KiB tolerance for format overhead
				finalReader = io.LimitReader(finalReader, limit)
			}
		}
	}

	// Prepare decrypted metadata (remove encryption and compression markers)
	decMetadata := make(map[string]string)
	for k, v := range expandedMetadata {
		// Skip encryption-related and compression-related metadata
		if IsEncryptionMetadata(k) || IsCompressionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Restore original size if available
	if originalSize, ok := expandedMetadata[MetaOriginalSize]; ok {
		decMetadata["Content-Length"] = originalSize
	}

	// Restore original ETag if available
	if originalETag, ok := expandedMetadata[MetaOriginalETag]; ok {
		decMetadata["ETag"] = originalETag
	}

	return finalReader, decMetadata, nil
}

// encryptChunked implements streaming chunked encryption.
func (e *engine) encryptChunked(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// Extract content type from metadata (no pre-read required).
	contentType := ""
	if metadata != nil {
		contentType = metadata["Content-Type"]
	}

	// Attempt to get original size and ETag from metadata set by the caller
	// (e.g., the handler populates these from HTTP headers).  When they are
	// absent we omit them rather than reading the entire source into memory.
	var originalSize int64
	if metadata != nil {
		if cl := metadata["Content-Length"]; cl != "" {
			if v, err := strconv.ParseInt(cl, 10, 64); err == nil {
				originalSize = v
			}
		} else if cl := metadata["x-amz-meta-original-content-length"]; cl != "" {
			if v, err := strconv.ParseInt(cl, 10, 64); err == nil {
				originalSize = v
			}
		}
	}
	// V1.0-OBS-1 G8: observe plaintext object size distribution when known.
	if e.observeEncryptedObjectBytes != nil && originalSize > 0 {
		e.observeEncryptedObjectBytes(originalSize)
	}
	originalETag := ""
	if metadata != nil {
		originalETag = metadata["ETag"]
	}

	// Prepare encryption metadata to check size
	encMetadata := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata {
			encMetadata[k] = v
		}
	}
	// Add basic encryption markers for size check
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaAlgorithm] = e.preferredAlgorithm
	if originalSize > 0 {
		encMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	}
	if originalETag != "" {
		encMetadata[MetaOriginalETag] = originalETag
	}
	// Add chunked-specific metadata
	encMetadata[MetaChunkedFormat] = "true"
	encMetadata[MetaChunkSize] = fmt.Sprintf("%d", e.chunkSize)

	// V1.0-CRYPTO-3: encrypt metadata blob if metadata key is configured.
	if e.metadataKey != nil {
		blob, err := e.encryptMetadata(encMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt metadata: %w", err)
		}
		for k := range encMetadata {
			if IsEncryptionMetadata(k) || IsCompressionMetadata(k) {
				delete(encMetadata, k)
			}
		}
		// MetaEncrypted (x-amz-meta-encrypted) MUST remain outside the blob
		// so that IsEncrypted works even without the metadata key (§2.6).
		encMetadata[MetaEncrypted] = "true"
		encMetadata[MetaEncryptedMetadata] = blob
	}

	// Check if we need fallback metadata storage
	if e.needsMetadataFallback(encMetadata) {
		return e.encryptChunkedWithMetadataFallback(ctx, reader, encMetadata, contentType, originalSize, originalETag)
	}

	// Determine algorithm to use
	algorithm := e.preferredAlgorithm

	// Generate salt and base IV for this encryption
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	baseIV, err := e.generateNonceForAlgorithm(algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate base IV: %w", err)
	}

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var (
		key      []byte
		envelope *KeyEnvelope
	)

	if e.kmsManager != nil {
		key, err = generateDataKey(keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
		}
		if e.rotationState != nil {
			e.rotationState.BeginWrap()
		}
		envelope, err = e.kmsManager.WrapKey(ctx, key, metadata)
		if e.rotationState != nil {
			e.rotationState.EndWrap()
		}
		if err != nil {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("failed to wrap data key: %w", err)
		}
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		// generateDataKey always returns exactly keySize bytes;
		// the following check is a defensive assertion.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: generateDataKey returned unexpected key size %d (want %d)", len(key), keySize)
		}
	} else {
		key, err = e.deriveKey(salt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	// Create cipher using selected algorithm
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create chunked encrypt reader directly from the source stream.
	// No io.ReadAll — memory usage is bounded by the chunk pipeline.
	chunkedReader, manifest := newChunkedEncryptReaderWithContext(ctx, reader, aead, baseIV, e.chunkSize, e.bufferPool)

	// Encode manifest for storage
	manifestEncoded, err := encodeManifest(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode manifest: %w", err)
	}

	// Prepare encryption metadata
	if metadata != nil {
		// Copy original metadata
		for k, v := range metadata {
			encMetadata[k] = v
		}
	}

	// Add chunked encryption markers
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaChunkedFormat] = "true"
	encMetadata[MetaAlgorithm] = algorithm
	encMetadata[MetaKeySalt] = encodeBase64(salt)
	encMetadata[MetaIV] = encodeBase64(baseIV)
	encMetadata[MetaChunkSize] = fmt.Sprintf("%d", e.chunkSize)
	encMetadata[MetaManifest] = manifestEncoded
	encMetadata[MetaIVDerivation] = "hkdf-sha256"
	encMetadata[MetaKDFParams] = FormatKDFParams(e.defaultKDFParams())
	if originalETag != "" {
		encMetadata[MetaOriginalETag] = originalETag
	}
	if originalSize > 0 {
		encMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	}
	// Note: MetaChunkCount is NOT set here because manifest.ChunkCount is 0 at this point
	// (it only gets incremented during encryption). ChunkCount can be calculated during
	// decryption from the encrypted object size and chunk size, or from the manifest if needed.
	// Some S3 implementations reject metadata with value "0", so we omit it.
	if envelope != nil {
		encMetadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		if envelope.KeyID != "" {
			encMetadata[MetaKMSKeyID] = envelope.KeyID
		}
		if envelope.Provider != "" {
			encMetadata[MetaKMSProvider] = envelope.Provider
		}
		encMetadata[MetaWrappedKeyCiphertext] = encodeBase64(envelope.Ciphertext)
	} else if kv, ok := metadata[MetaKeyVersion]; ok && kv != "" {
		encMetadata[MetaKeyVersion] = kv
	}

	// Compact metadata according to provider profile
	compactedMetadata, err := e.compactor.CompactMetadata(encMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compact metadata: %w", err)
	}

	return chunkedReader, compactedMetadata, nil
}

// encryptChunkedWithMetadataFallback encrypts chunked data with metadata stored in object body
func (e *engine) encryptChunkedWithMetadataFallback(ctx context.Context, reader io.Reader, fullMetadata map[string]string, contentType string, originalSize int64, originalETag string) (io.Reader, map[string]string, error) {
	// Generate encryption parameters
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	baseIV, err := e.generateNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate base IV: %w", err)
	}

	algorithm := e.preferredAlgorithm

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var (
		key      []byte
		envelope *KeyEnvelope
	)

	if e.kmsManager != nil {
		key, err = generateDataKey(keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
		}
		if e.rotationState != nil {
			e.rotationState.BeginWrap()
		}
		envelope, err = e.kmsManager.WrapKey(ctx, key, fullMetadata)
		if e.rotationState != nil {
			e.rotationState.EndWrap()
		}
		if err != nil {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("failed to wrap data key: %w", err)
		}
		fullMetadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		// generateDataKey always returns exactly keySize bytes;
		// the following check is a defensive assertion.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: generateDataKey returned unexpected key size %d (want %d)", len(key), keySize)
		}
	} else {
		key, err = e.deriveKey(salt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	// Create cipher
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Build the per-chunk streaming reader. This is the only encryption layer
	// for the fallback-v2 format; the outer AEAD Seal used by the legacy
	// fallback-v1 format is eliminated here. Each chunk is already authenticated
	// by the chunked AEAD, so a second full-object Seal is both redundant and
	// forces 2× peak memory allocation (chunkedBuf + Seal output).
	chunkedReader, manifest := newChunkedEncryptReaderWithContext(ctx, reader, aead, baseIV, e.chunkSize, e.bufferPool)

	// Encode manifest
	manifestEncoded, err := encodeManifest(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode manifest: %w", err)
	}

	// Update full metadata with chunked encryption info (stored in the object body)
	fullMetadata[MetaChunkedFormat] = "true"
	fullMetadata[MetaAlgorithm] = algorithm
	fullMetadata[MetaKeySalt] = encodeBase64(salt)
	fullMetadata[MetaIV] = encodeBase64(baseIV)
	fullMetadata[MetaChunkSize] = fmt.Sprintf("%d", e.chunkSize)
	fullMetadata[MetaManifest] = manifestEncoded
	fullMetadata[MetaIVDerivation] = "hkdf-sha256"
	fullMetadata[MetaKDFParams] = FormatKDFParams(e.defaultKDFParams())
	if originalETag != "" {
		fullMetadata[MetaOriginalETag] = originalETag
	}
	if originalSize > 0 {
		fullMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	}
	if envelope != nil {
		fullMetadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		if envelope.KeyID != "" {
			fullMetadata[MetaKMSKeyID] = envelope.KeyID
		}
		if envelope.Provider != "" {
			fullMetadata[MetaKMSProvider] = envelope.Provider
		}
		fullMetadata[MetaWrappedKeyCiphertext] = encodeBase64(envelope.Ciphertext)
	}

	// Serialize full metadata to JSON (stored in the object body as a prefix)
	metadataJSON, err := encodeMetadataToJSON(fullMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode metadata: %w", err)
	}

	// Build the 4-byte big-endian metadata-length header.
	// This is the only allocation in the encrypt hot path; it is O(1) regardless
	// of object size, as opposed to the legacy path which allocated O(objectSize).
	metadataLen := uint32(len(metadataJSON)) // #nosec G115 — metadata length bounded by max metadata size (<< 2^32)
	headerBuf := []byte{
		byte(metadataLen >> 24), // #nosec G115
		byte(metadataLen >> 16), // #nosec G115
		byte(metadataLen >> 8),  // #nosec G115
		byte(metadataLen),       // #nosec G115 — 4-byte big-endian encoding of metadata header
	}

	// Stream: [4-byte header][metadata JSON][chunked ciphertext stream]
	// Peak memory ≈ len(headerBuf) + len(metadataJSON) — bounded by metadata, not by object size.
	streamingReader := io.MultiReader(
		bytes.NewReader(headerBuf),
		bytes.NewReader(metadataJSON),
		chunkedReader,
	)

	// Create minimal header metadata (what goes into S3 object metadata headers)
	minimalMetadata := map[string]string{
		MetaEncrypted:       "true",
		MetaFallbackMode:    "true",
		MetaFallbackVersion: "2", // streaming chunked format; no outer AEAD wrapper
		MetaAlgorithm:       algorithm,
		MetaKeySalt:         encodeBase64(salt),
		MetaIV:              encodeBase64(baseIV),
	}
	if originalSize > 0 {
		minimalMetadata[MetaOriginalSize] = fmt.Sprintf("%d", originalSize)
	}
	if originalETag != "" {
		minimalMetadata[MetaOriginalETag] = originalETag
	}
	if envelope != nil {
		minimalMetadata[MetaKeyVersion] = fmt.Sprintf("%d", envelope.KeyVersion)
		if envelope.KeyID != "" {
			minimalMetadata[MetaKMSKeyID] = envelope.KeyID
		}
		if envelope.Provider != "" {
			minimalMetadata[MetaKMSProvider] = envelope.Provider
		}
		minimalMetadata[MetaWrappedKeyCiphertext] = encodeBase64(envelope.Ciphertext)
	}

	// Copy original user metadata (non-encryption, non-compression keys)
	for k, v := range fullMetadata {
		if !IsEncryptionMetadata(k) && !IsCompressionMetadata(k) {
			minimalMetadata[k] = v
		}
	}

	// Preserve MetaContentType in minimal headers for AAD reconstruction.
	if ct := fullMetadata[MetaContentType]; ct != "" {
		minimalMetadata[MetaContentType] = ct
	}

	return streamingReader, minimalMetadata, nil
}

// decryptChunked implements streaming chunked decryption.
func (e *engine) decryptChunked(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// V1.0-CRYPTO-3: decrypt encrypted metadata blob if metadata key is configured.
	if e.metadataKey != nil {
		blobKey := MetaEncryptedMetadata
		if _, ok := metadata[MetaEncryptedMetadataCompact]; ok {
			blobKey = MetaEncryptedMetadataCompact
		}
		if blob, ok := metadata[blobKey]; ok && blob != "" {
			decryptedMeta, err := e.decryptMetadata(blob)
			if err != nil {
				return nil, nil, fmt.Errorf("decrypt metadata: %w", err)
			}
			for k, v := range decryptedMeta {
				metadata[k] = v
			}
			delete(metadata, blobKey)
		}
	}

	// Load manifest from metadata
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Extract encryption parameters from metadata
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Get algorithm from metadata (default to AES-GCM for backward compatibility)
	algorithm := metadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s (not in supported list)", algorithm)
	}

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var (
		key []byte
	)

	if e.kmsManager != nil && metadata[MetaWrappedKeyCiphertext] != "" {
		wrapped, err := decodeBase64(metadata[MetaWrappedKeyCiphertext])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode wrapped data key: %w", err)
		}
		env := &KeyEnvelope{
			KeyID:      metadata[MetaKMSKeyID],
			KeyVersion: parseKeyVersion(metadata[MetaKeyVersion]),
			Provider:   metadata[MetaKMSProvider],
			Ciphertext: wrapped,
		}
		key, err = e.kmsManager.UnwrapKey(ctx, env, metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unwrap data key: %w", err)
		}
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("failed to unwrap data key: KMS returned key of size %d, expected %d", len(key), keySize)
		}
	} else {
		// Read KDF params; absent -> legacy 100k PBKDF2.
		kdfParams, err := ParseKDFParams(metadata[MetaKDFParams])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse KDF params: %w", err)
		}
		key, err = e.deriveKeyWithParams(salt, kdfParams)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	// Create cipher using algorithm from metadata
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create chunked decrypt reader
	chunkedReader, err := newChunkedDecryptReaderWithContext(ctx, reader, aead, manifest, e.bufferPool)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create chunked decrypt reader: %w", err)
	}

	// Prepare decrypted metadata (remove encryption markers)
	decMetadata := make(map[string]string)
	for k, v := range metadata {
		// Skip encryption-related metadata
		if IsEncryptionMetadata(k) {
			continue
		}
		// For chunked encryption, skip ETag and Content-Length from GetObject
		// (they're for the encrypted object, not the plaintext)
		// We'll restore them below from original values
		if k == "ETag" || k == "Content-Length" {
			continue
		}
		decMetadata[k] = v
	}

	// Restore original size if available (prefer MetaOriginalSize, fallback to calculation)
	if originalSize, ok := metadata[MetaOriginalSize]; ok {
		decMetadata["Content-Length"] = originalSize
	} else if chunkCount, ok := metadata[MetaChunkCount]; ok {
		if chunkSize, ok2 := metadata[MetaChunkSize]; ok2 {
			count, err1 := strconv.Atoi(chunkCount)
			size, err2 := strconv.Atoi(chunkSize)
			if err1 == nil && err2 == nil {
				// Approximate original size (last chunk might be smaller)
				approxSize := int64((count-1)*size + size)
				decMetadata["Content-Length"] = fmt.Sprintf("%d", approxSize)
			}
		}
	}

	// Restore original ETag if available (only restore if we have it, otherwise don't include ETag)
	if originalETag, ok := metadata[MetaOriginalETag]; ok && originalETag != "" {
		decMetadata["ETag"] = originalETag
	}

	return chunkedReader, decMetadata, nil
}

// DecryptRange decrypts only the chunks needed for a specific plaintext range.
// This optimizes range requests by decrypting only necessary chunks.
func (e *engine) DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error) {
	if !e.IsEncrypted(metadata) {
		return nil, nil, fmt.Errorf("object is not encrypted")
	}

	// Expand compacted metadata first
	expandedMetadata, err := e.compactor.ExpandMetadata(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to expand metadata: %w", err)
	}

	// V1.0-CRYPTO-3: decrypt encrypted metadata blob if metadata key is configured.
	if e.metadataKey != nil {
		blobKey := MetaEncryptedMetadata
		if _, ok := expandedMetadata[MetaEncryptedMetadataCompact]; ok {
			blobKey = MetaEncryptedMetadataCompact
		}
		if blob, ok := expandedMetadata[blobKey]; ok && blob != "" {
			decryptedMeta, err := e.decryptMetadata(blob)
			if err != nil {
				return nil, nil, fmt.Errorf("decrypt metadata: %w", err)
			}
			for k, v := range decryptedMeta {
				expandedMetadata[k] = v
			}
			delete(expandedMetadata, blobKey)
		}
	}

	// Only supports chunked format for range optimization
	if !isChunkedFormat(expandedMetadata) {
		return nil, nil, fmt.Errorf("range optimization only supported for chunked format")
	}

	// Get plaintext size for validation
	plaintextSize, err := GetPlaintextSizeFromMetadata(expandedMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get plaintext size: %w", err)
	}

	// Validate range (similar to HTTP range validation)
	if plaintextStart < 0 || plaintextStart >= plaintextSize || plaintextEnd < plaintextStart || plaintextEnd >= plaintextSize {
		return nil, nil, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", plaintextStart, plaintextEnd, plaintextSize)
	}

	// Load manifest
	manifest, err := loadManifestFromMetadata(expandedMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Compute ChunkCount if missing from the manifest. The encrypt path does
	// not populate manifest.ChunkCount (see chunked.go: it's incremented at
	// read-time, and metadata is snapshotted before any reads). For the
	// regular GET path this is benign because Decrypt streams the whole
	// object; for DecryptRange we need the count up-front. Derive it from
	// the original plaintext size and chunk size (both always in metadata).
	if manifest.ChunkCount == 0 && manifest.ChunkSize > 0 && plaintextSize > 0 {
		manifest.ChunkCount = int((plaintextSize + int64(manifest.ChunkSize) - 1) / int64(manifest.ChunkSize))
	}

	// Extract encryption parameters
	salt, err := decodeBase64(expandedMetadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	baseIV, err := decodeBase64(expandedMetadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base IV: %w", err)
	}

	// Get algorithm from metadata
	algorithm := expandedMetadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s", algorithm)
	}

	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}

	var (
		key []byte
	)

	if e.kmsManager != nil && expandedMetadata[MetaWrappedKeyCiphertext] != "" {
		wrapped, err := decodeBase64(expandedMetadata[MetaWrappedKeyCiphertext])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode wrapped data key: %w", err)
		}
		env := &KeyEnvelope{
			KeyID:      expandedMetadata[MetaKMSKeyID],
			KeyVersion: parseKeyVersion(expandedMetadata[MetaKeyVersion]),
			Provider:   expandedMetadata[MetaKMSProvider],
			Ciphertext: wrapped,
		}
		key, err = e.kmsManager.UnwrapKey(ctx, env, expandedMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unwrap data key: %w", err)
		}
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("failed to unwrap data key: KMS returned key of size %d, expected %d", len(key), keySize)
		}
	} else {
		// Read KDF params; absent -> legacy 100k PBKDF2.
		kdfParams, err := ParseKDFParams(expandedMetadata[MetaKDFParams])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse KDF params: %w", err)
		}
		key, err = e.deriveKeyWithParams(salt, kdfParams)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive key: %w", err)
		}
		// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
		// the following size check is a defensive assertion only.
		if len(key) != keySize {
			zeroBytes(key)
			return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
		}
	}
	defer zeroBytes(key)

	// Create cipher
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead := aeadCipher.(cipher.AEAD)

	// Create range-aware decrypt reader
	rangeReader, err := newRangeDecryptReader(reader, aead, manifest, baseIV, plaintextStart, plaintextEnd, e.bufferPool)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create range reader: %w", err)
	}

	// Prepare decrypted metadata
	decMetadata := make(map[string]string)
	for k, v := range expandedMetadata {
		if IsEncryptionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Set Content-Length to the range size
	rangeSize := plaintextEnd - plaintextStart + 1
	decMetadata["Content-Length"] = fmt.Sprintf("%d", rangeSize)

	return rangeReader, decMetadata, nil
}

// needsMetadataFallback checks if metadata would overflow provider limits
func (e *engine) needsMetadataFallback(metadata map[string]string) bool {
	// Skip fallback check if provider has unlimited headers
	if e.providerProfile.TotalHeaderLimit <= 0 {
		return false
	}

	// Try compacting first
	compacted, err := e.compactor.CompactMetadata(metadata)
	if err != nil {
		// If compaction fails, we definitely need fallback
		return true
	}

	// Check if compacted metadata fits
	return EstimateMetadataSize(compacted) > e.providerProfile.TotalHeaderLimit
}

// encryptWithMetadataFallback encrypts data with metadata stored in object body
func (e *engine) encryptWithMetadataFallback(plaintext []byte, fullMetadata map[string]string, contentType string, originalSize int64, originalETag string) (io.Reader, map[string]string, error) {
	// Apply compression if enabled (same logic as normal encryption).
	// Read the (possibly compressed) payload into a single byte slice so we
	// can build the AEAD plaintext in one allocation and avoid holding
	// multiple full-size copies of the object.
	data := plaintext
	compressionMetadata := make(map[string]string)
	if e.compressionEngine != nil {
		compressedReader, compMeta, err := e.compressionEngine.Compress(bytes.NewReader(plaintext), contentType, originalSize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compress data: %w", err)
		}
		if compMeta != nil {
			// Compression was applied and was beneficial.
			compressionMetadata = compMeta
			compressedData, err := io.ReadAll(compressedReader)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read compressed data: %w", err)
			}
			data = compressedData
		}
	}

	// Merge compression metadata into full metadata
	for k, v := range compressionMetadata {
		fullMetadata[k] = v
	}

	// Generate encryption parameters
	salt, err := e.generateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce, err := e.generateNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	algorithm := e.preferredAlgorithm

	// Derive key
	key, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Adjust key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
	// the following size check is a defensive assertion only.
	if len(key) != keySize {
		zeroBytes(key)
		return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
	}

	// Create cipher
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher for algorithm %s: %w", algorithm, err)
	}

	// Serialize full metadata to JSON
	metadataJSON, err := encodeMetadataToJSON(fullMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode metadata: %w", err)
	}

	// Build a single plaintext buffer for the AEAD Seal call to avoid holding
	// intermediate copies (finalData + dataToEncryptFinal) on top of the
	// caller's plaintext slice.
	metadataLen := uint32(len(metadataJSON)) // #nosec G115 — metadata length bounded
	ptSize := 4 + len(metadataJSON) + len(data)
	pt := make([]byte, ptSize)
	pt[0] = byte(metadataLen >> 24) // #nosec G115
	pt[1] = byte(metadataLen >> 16) // #nosec G115
	pt[2] = byte(metadataLen >> 8)  // #nosec G115
	pt[3] = byte(metadataLen)       // #nosec G115 — 4-byte big-endian encoding of metadata header
	copy(pt[4:], metadataJSON)
	copy(pt[4+len(metadataJSON):], data)

	// Build AAD for authentication
	aad := buildAAD(algorithm, salt, nonce, map[string]string{
		"Content-Type":   contentType,
		MetaOriginalSize: fmt.Sprintf("%d", originalSize),
	})

	// Encrypt the combined data
	ciphertext := aeadCipher.Seal(nil, nonce, pt, aad)

	// Zeroize the intermediate plaintext buffer to minimise key material lifetime.
	zeroBytes(pt)

	// Create minimal header metadata
	minimalMetadata := map[string]string{
		MetaEncrypted:    "true",
		MetaFallbackMode: "true",
		MetaAlgorithm:    algorithm,
		MetaKeySalt:      encodeBase64(salt),
		MetaIV:           encodeBase64(nonce),
		MetaOriginalSize: fmt.Sprintf("%d", originalSize),
		MetaOriginalETag: originalETag,
		MetaKDFParams:    FormatKDFParams(e.defaultKDFParams()),
	}

	// Copy original user metadata
	for k, v := range fullMetadata {
		if !IsEncryptionMetadata(k) && !IsCompressionMetadata(k) {
			minimalMetadata[k] = v
		}
	}

	// Preserve MetaContentType in minimal headers so the decrypt path can
	// reconstruct AAD without falling back to the S3 Content-Type header.
	if ct := fullMetadata[MetaContentType]; ct != "" {
		minimalMetadata[MetaContentType] = ct
	}

	return bytes.NewReader(ciphertext), minimalMetadata, nil
}

// isFallbackMode checks if the metadata indicates fallback mode
func (e *engine) isFallbackMode(metadata map[string]string) bool {
	fallback, ok := metadata[MetaFallbackMode]
	return ok && fallback == "true"
}

// decryptWithMetadataFallback decrypts data with metadata stored in object body
func (e *engine) decryptWithMetadataFallback(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// V1.0-SEC-27: dispatch on the on-disk format version stored in header metadata.
	//
	// Version "2" (MetaFallbackVersion == "2"): streaming format written by the
	// fixed encryptChunkedWithMetadataFallback. The object body is:
	//   [4-byte BE metadata_length][metadata_json][chunked_ciphertext_stream]
	// There is no outer AEAD wrapper; per-chunk AEAD integrity is provided by
	// the chunked layer. Decryption delegates to decryptChunked after parsing
	// the in-body metadata prefix, which is fully streaming — no io.ReadAll.
	//
	// Legacy / absent version: the object was encrypted by the old code which
	// wrapped the chunked ciphertext in a second outer AEAD Seal. Handled by
	// decryptFallbackV1 for backward compatibility.
	if metadata[MetaFallbackVersion] == "2" {
		return e.decryptFallbackV2(ctx, reader, metadata)
	}
	return e.decryptFallbackV1(reader, metadata)
}

// decryptFallbackV2 decrypts objects written by the fixed (V1.0-SEC-27) fallback
// encrypt path. Format: [4-byte BE metadata_length][metadata_json][chunked_stream].
// No outer AEAD — integrity comes from the per-chunk AEAD in the chunked layer.
func (e *engine) decryptFallbackV2(ctx context.Context, reader io.Reader, headerMetadata map[string]string) (io.Reader, map[string]string, error) {
	// Read the 4-byte big-endian metadata length prefix.
	var lenBuf [4]byte
	if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("fallback-v2: failed to read metadata length prefix: %w", err)
	}
	metadataLen := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])

	// Guard against malformed/truncated objects. The metadata JSON is small
	// (headers < 8 KiB in practice); cap at 1 MiB to prevent heap abuse.
	const maxFallbackMetadataBytes = 1 << 20 // 1 MiB
	if metadataLen > maxFallbackMetadataBytes {
		return nil, nil, fmt.Errorf("fallback-v2: metadata length %d exceeds sanity limit %d", metadataLen, maxFallbackMetadataBytes)
	}

	// Read the metadata JSON (bounded by metadataLen).
	metadataJSON := make([]byte, metadataLen)
	if _, err := io.ReadFull(reader, metadataJSON); err != nil {
		return nil, nil, fmt.Errorf("fallback-v2: failed to read metadata JSON (%d bytes): %w", metadataLen, err)
	}

	// Parse the full metadata that was embedded in the object body.
	fullMetadata, err := decodeMetadataFromJSON(metadataJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("fallback-v2: failed to decode in-body metadata: %w", err)
	}

	// The remainder of reader is the raw chunked ciphertext stream. Delegate
	// to decryptChunked which is fully streaming — no io.ReadAll required.
	return e.decryptChunked(ctx, reader, fullMetadata)
}

// decryptFallbackV1 decrypts objects written by the legacy fallback encrypt path
// (before V1.0-SEC-27). The object body is the output of aead.Seal applied over
// [4-byte metadata_length][metadata_json][chunked_ciphertext]. This path is kept
// for backward compatibility with objects already stored in S3.
//
// Deprecated: new objects are written using the streaming v2 format.
// This path may be removed no earlier than v3.0.
func (e *engine) decryptFallbackV1(reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	// Extract encryption parameters from header metadata
	salt, err := decodeBase64(metadata[MetaKeySalt])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	iv, err := decodeBase64(metadata[MetaIV])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	algorithm := metadata[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	// Verify algorithm is supported
	if !isAlgorithmSupported(algorithm, e.supportedAlgorithms) {
		return nil, nil, fmt.Errorf("unsupported algorithm %s (not in supported list)", algorithm)
	}

	// Read KDF params; absent -> legacy 100k PBKDF2.
	kdfParams, err := ParseKDFParams(metadata[MetaKDFParams])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse KDF params: %w", err)
	}
	// Derive key
	key, err := e.deriveKeyWithParams(salt, kdfParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(key)

	// Adjust key size for algorithm
	keySize := aesKeySize
	if algorithm == AlgorithmChaCha20Poly1305 {
		keySize = chacha20KeySize
	}
	// deriveKey always returns exactly aesKeySize bytes via PBKDF2;
	// the following size check is a defensive assertion only.
	if len(key) != keySize {
		zeroBytes(key)
		return nil, nil, fmt.Errorf("internal: PBKDF2 returned unexpected key size %d (want %d)", len(key), keySize)
	}

	// Create cipher
	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Read all encrypted data (legacy path requires full materialization due to outer AEAD Seal)
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Build AAD from available metadata.
	//
	// For legacy fallback-v1 objects the full metadata (including MetaContentType)
	// is stored inside the encrypted body, so it is not available until after
	// decryption.  The only Content-Type value we have in the header metadata is
	// the "Content-Type" key that was copied to the minimal headers (it is not
	// classified as encryption metadata).  We therefore fall back to it when
	// MetaContentType is absent.  This is safe for objects created through the
	// gateway because the gateway always stores a deterministic Content-Type with
	// S3, so the value returned in a GetObject response matches the value that
	// was fed into the AAD at encryption time.  New fallback objects set
	// MetaContentType explicitly in the minimal headers, so the fallback is only
	// required for objects created before that change.
	contentType := metadata[MetaContentType]
	if contentType == "" {
		contentType = metadata["Content-Type"]
	}
	originalSize := metadata[MetaOriginalSize]
	aadMeta := map[string]string{
		"Content-Type":   contentType,
		MetaOriginalSize: originalSize,
	}
	aad := buildAAD(algorithm, salt, iv, aadMeta)

	// Decrypt the data (try new format first, then legacy)
	plaintext, err := aeadCipher.Open(nil, iv, ciphertext, aad)
	if err != nil {
		aadLegacy := buildAADLegacy(algorithm, salt, iv, aadMeta)
		plaintext, err = aeadCipher.Open(nil, iv, ciphertext, aadLegacy)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
	}

	// Parse the decrypted data: [metadata_length][metadata_json][actual_data]
	if len(plaintext) < 4 {
		return nil, nil, fmt.Errorf("encrypted data too short for fallback format")
	}

	metadataLen := uint32(plaintext[0])<<24 | uint32(plaintext[1])<<16 | uint32(plaintext[2])<<8 | uint32(plaintext[3])
	if metadataLen > uint32(len(plaintext)-4) { // #nosec G115 — len(plaintext) >= 4 guarded by check above
		return nil, nil, fmt.Errorf("invalid metadata length in fallback format")
	}

	metadataStart := 4
	metadataEnd := metadataStart + int(metadataLen)
	metadataJSON := plaintext[metadataStart:metadataEnd]
	actualData := plaintext[metadataEnd:]

	// Parse metadata from JSON
	fullMetadata, err := decodeMetadataFromJSON(metadataJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode metadata from fallback: %w", err)
	}

	// Apply decompression if needed
	var finalReader io.Reader = bytes.NewReader(actualData)
	if e.compressionEngine != nil {
		decompressedReader, err := e.compressionEngine.Decompress(bytes.NewReader(actualData), fullMetadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress data: %w", err)
		}
		finalReader = decompressedReader
		// V1.0-SEC-M05: bound decompressed output to prevent decompression bombs
		if originalSizeStr, ok := fullMetadata[MetaCompressionOriginalSize]; ok {
			if originalSize, err := strconv.ParseInt(originalSizeStr, 10, 64); err == nil && originalSize > 0 {
				limit := originalSize + 65536 // 64 KiB tolerance for format overhead
				finalReader = io.LimitReader(finalReader, limit)
			}
		}
	}

	// Prepare decrypted metadata (remove encryption and compression markers)
	decMetadata := make(map[string]string)
	for k, v := range fullMetadata {
		// Skip encryption-related and compression-related metadata
		if IsEncryptionMetadata(k) || IsCompressionMetadata(k) {
			continue
		}
		decMetadata[k] = v
	}

	// Restore original size if available
	if originalSize, ok := fullMetadata[MetaOriginalSize]; ok {
		decMetadata["Content-Length"] = originalSize
	}

	// Restore original ETag if available
	if originalETag, ok := fullMetadata[MetaOriginalETag]; ok {
		decMetadata["ETag"] = originalETag
	}

	return finalReader, decMetadata, nil
}

// IsEncrypted checks if the metadata indicates the object is encrypted.
func (e *engine) IsEncrypted(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}

	// Check for full key first
	if encrypted, ok := metadata[MetaEncrypted]; ok && encrypted == "true" {
		return true
	}

	// Check for compacted key
	if encrypted, ok := metadata["x-amz-meta-e"]; ok && encrypted == "true" {
		return true
	}

	return false
}

// computeETag is implemented in etag_default.go (non-FIPS) and etag_fips.go (FIPS build).
// S3 treats ETags as opaque identifiers; both MD5 and SHA-256 are functionally equivalent
// for this gateway's purposes.

// IsEncryptionMetadata checks if a metadata key is related to encryption.
func IsEncryptionMetadata(key string) bool {
	return key == MetaEncrypted ||
		key == MetaAlgorithm ||
		key == MetaKeySalt ||
		key == MetaIV ||
		key == MetaAuthTag ||
		key == MetaOriginalSize ||
		key == MetaOriginalETag ||
		key == MetaContentType ||
		key == MetaChunkedFormat ||
		key == MetaChunkSize ||
		key == MetaChunkCount ||
		key == MetaManifest ||
		key == MetaKeyVersion ||
		key == MetaWrappedKeyCiphertext ||
		key == MetaKMSKeyID ||
		key == MetaKMSProvider ||
		key == MetaFallbackMode ||
		key == MetaFallbackPointer ||
		key == MetaFallbackVersion ||
		key == MetaIVDerivation ||
		key == MetaLegacyNoAAD ||
		key == MetaKDFParams
}

// IsCompressionMetadata checks if a metadata key is related to compression.
func IsCompressionMetadata(key string) bool {
	return key == MetaCompression ||
		key == MetaCompressionEnabled ||
		key == MetaCompressionAlgorithm ||
		key == MetaCompressionOriginalSize
}

// buildAADLegacy is the old pipe-delimited AAD format.
// Kept for backward compatibility when decrypting objects created
// before the AAD canonicalization fix (V1.0-SEC-H01).
func buildAADLegacy(algorithm string, salt, nonce []byte, meta map[string]string) []byte {
	var b bytes.Buffer
	b.WriteString("alg:")
	b.WriteString(algorithm)
	b.WriteString("|salt:")
	b.WriteString(encodeBase64(salt))
	b.WriteString("|iv:")
	b.WriteString(encodeBase64(nonce))
	if kv := meta[MetaKeyVersion]; kv != "" {
		b.WriteString("|kv:")
		b.WriteString(kv)
	}
	if ct := meta["Content-Type"]; ct != "" {
		b.WriteString("|ct:")
		b.WriteString(ct)
	}
	if osz := meta[MetaOriginalSize]; osz != "" {
		b.WriteString("|osz:")
		b.WriteString(osz)
	}
	return b.Bytes()
}

// buildAAD constructs additional authenticated data from stable metadata fields.
// Uses length-prefixed encoding to prevent injection attacks (V1.0-SEC-H01).
// Fields are written in a fixed canonical order.
func buildAAD(algorithm string, salt, nonce []byte, meta map[string]string) []byte {
	var b bytes.Buffer
	writeLengthPrefixed(&b, []byte(algorithm))
	writeLengthPrefixed(&b, salt)
	writeLengthPrefixed(&b, nonce)
	// Fixed order for canonicalization
	writeLengthPrefixed(&b, []byte(meta[MetaKeyVersion]))
	writeLengthPrefixed(&b, []byte(meta["Content-Type"]))
	writeLengthPrefixed(&b, []byte(meta[MetaOriginalSize]))
	return b.Bytes()
}

// writeLengthPrefixed writes data to buf prefixed with its length as a big-endian uint32.
func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(len(data))) // #nosec G115 — data is AAD metadata, bounded by object metadata size
	buf.Write(tmp[:])
	buf.Write(data)
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseKeyVersion(value string) int {
	if value == "" {
		return 0
	}
	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return 0
}

// encodeMetadataToJSON encodes metadata map to JSON bytes
func encodeMetadataToJSON(metadata map[string]string) ([]byte, error) {
	return json.Marshal(metadata)
}

// decodeMetadataFromJSON decodes JSON bytes to metadata map
func decodeMetadataFromJSON(data []byte) (map[string]string, error) {
	var metadata map[string]string
	err := json.Unmarshal(data, &metadata)
	return metadata, err
}

// Close zeroizes sensitive key material held by the engine (the master password
// bytes) so they do not linger on the heap after the engine is no longer needed.
// It is safe to call Close multiple times; subsequent calls are no-ops.
//
// Usage: obtain the engine as io.Closer via type assertion:
//
//	if c, ok := eng.(io.Closer); ok { defer c.Close() }
func (e *engine) Close() error {
	zeroBytes(e.password)
	return nil
}
