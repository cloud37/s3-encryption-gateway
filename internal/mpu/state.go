// Package mpu implements the encrypted multipart upload state store.
// It provides persistence for per-upload encryption state (DEK, IV prefix,
// per-part records) using Valkey (Redis-compatible) as the backend.
package mpu

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/internal/metrics"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

// Sentinel errors — use errors.Is for matching.
var (
	ErrUploadNotFound      = errors.New("mpu: upload not found")
	ErrUploadAlreadyExists = errors.New("mpu: upload already exists")
	ErrStateUnavailable    = errors.New("mpu: state store unavailable")
	ErrStateDecryptFailed  = errors.New("mpu: state decrypt failed")
)

// Versioned ciphertext format for at-rest encryption of state blobs.
// Layout: version(1 byte) || nonce(12 bytes) || ciphertext(...) || tag(16 bytes)
const (
	stateEncryptionVersionLen = 1
	stateEncryptionNonceLen   = 12
	stateEncryptionTagLen     = 16
	stateEncryptionVersionV1  byte = 0x01
)

// PartRecord holds per-part encryption metadata persisted in Valkey.
type PartRecord struct {
	PartNumber int32  `json:"pn"`
	ETag       string `json:"etag"`
	PlainLen   int64  `json:"plain_len"`
	EncLen     int64  `json:"enc_len"`
	ChunkCount int32  `json:"chunks"`
}

// UploadState holds the encryption state for an in-flight multipart upload.
type UploadState struct {
	UploadID     string `json:"upload_id"`
	Bucket       string `json:"bucket"`
	Key          string `json:"key"`
	// UploadIDHash is hex(sha256(uploadID)) — stored so IVs can be reconstructed
	// during decryption without re-querying the state.
	UploadIDHash string `json:"uid_hash"`
	// WrappedDEK is the JSON-serialised KeyEnvelope from the KeyManager.
	WrappedDEK  string `json:"wrapped_dek"`
	// IVPrefixHex is the hex-encoded 12-byte IV prefix used for per-part IV derivation.
	IVPrefixHex string `json:"iv_prefix"`
	Algorithm   string `json:"algorithm"`
	ChunkSize   int    `json:"chunk_size"`
	// KMSKeyID and KMSProvider are copied from the KeyEnvelope for quick access.
	KMSKeyID      string `json:"kms_key_id,omitempty"`
	KMSProvider   string `json:"kms_provider,omitempty"`
	KMSKeyVersion int    `json:"kms_key_ver,omitempty"`
	// PolicySnapshot captures EncryptMultipartUploads and other relevant policy
	// fields at CreateMultipartUpload time so later operations use consistent policy.
	PolicySnapshot PolicySnapshot `json:"policy"`
	Parts          []PartRecord   `json:"parts,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// PolicySnapshot captures the policy fields that affect multipart encryption.
type PolicySnapshot struct {
	EncryptMultipartUploads bool `json:"encrypt_mpu"`
}

// StateStore is the persistence interface for in-flight multipart upload state.
type StateStore interface {
	// Create persists a new UploadState. Returns ErrUploadAlreadyExists if the
	// key already exists (idempotency guard).
	Create(ctx context.Context, state *UploadState) error

	// Get retrieves the UploadState for uploadID. Returns ErrUploadNotFound if
	// the key does not exist or has expired.
	Get(ctx context.Context, uploadID string) (*UploadState, error)

	// AppendPart appends a PartRecord and refreshes the TTL.
	AppendPart(ctx context.Context, uploadID string, part PartRecord) error

	// Delete removes the upload state. Safe to call on missing keys.
	Delete(ctx context.Context, uploadID string) error

	// List returns all active multipart uploads by scanning the store.
	List(ctx context.Context) ([]UploadState, error)

	// HealthCheck performs a lightweight liveness check against Valkey.
	HealthCheck(ctx context.Context) error

	// Close releases resources. Idempotent.
	Close() error
}

// uploadKey returns the Valkey hash key for an upload: mpu:<hex(sha256(uploadID))>.
func uploadKey(uploadID string) string {
	h := sha256.Sum256([]byte(uploadID))
	return "mpu:" + hex.EncodeToString(h[:])
}

const (
	fieldMeta = "meta"
	fieldPartPrefix = "part:"
)

// ValkeyStateStore implements StateStore backed by Valkey (via go-redis/v9).
type ValkeyStateStore struct {
	client       redis.UniversalClient
	ttl          time.Duration
	stateKey     []byte
	encryptState bool
	legacyWarn   sync.Once
	// metrics is optional; when non-nil, encryption counters are reported.
	metrics *metrics.Metrics
}

// NewValkeyStateStore constructs a ValkeyStateStore from cfg and performs a
// HealthCheck. Returns an error (fail-closed) if Valkey is unreachable.
// encryptionPassword is the main gateway encryption password, used as fallback
// when cfg.EncryptionPasswordEnv is not set.
func NewValkeyStateStore(ctx context.Context, cfg config.ValkeyConfig, encryptionPassword string) (*ValkeyStateStore, error) {
	password := ""
	if cfg.PasswordEnv != "" {
		password = os.Getenv(cfg.PasswordEnv)
	}

	var tlsCfg *tls.Config
	if cfg.TLS.Enabled {
		tc, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("mpu: valkey TLS config: %w", err)
		}
		tlsCfg = tc
	} else if !cfg.InsecureAllowPlaintext {
		return nil, fmt.Errorf("%w: TLS is required (set insecure_allow_plaintext=true to override in dev)", ErrStateUnavailable)
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Duration(config.ValkeyDefaultTTLSeconds) * time.Second
	}

	opts := &redis.UniversalOptions{
		Addrs:        []string{cfg.Addr},
		Username:     cfg.Username,
		Password:     password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		TLSConfig:    tlsCfg,
	}

	client := redis.NewUniversalClient(opts)

	// Derive at-rest encryption key.
	encryptState := cfg.EncryptState == nil || *cfg.EncryptState
	var stateKey []byte
	if encryptState {
		encPassword := ""
		if cfg.EncryptionPasswordEnv != "" {
			encPassword = os.Getenv(cfg.EncryptionPasswordEnv)
		} else {
			encPassword = encryptionPassword
		}
		if encPassword == "" {
			_ = client.Close()
			return nil, fmt.Errorf("%w: valkey state encryption enabled but no encryption password available (set %s or configure encryption.password)", ErrStateUnavailable, cfg.EncryptionPasswordEnv)
		}
		stateKey = deriveStateAEADKey(encPassword)
	}

	s := &ValkeyStateStore{
		client:       client,
		ttl:          ttl,
		stateKey:     stateKey,
		encryptState: encryptState,
	}

	// Fail-closed: if Valkey is unreachable at startup, refuse to start.
	if err := s.HealthCheck(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("%w: %v", ErrStateUnavailable, err)
	}
	return s, nil
}

// buildTLSConfig constructs a *tls.Config from ValkeyTLSConfig.
func buildTLSConfig(cfg config.ValkeyTLSConfig) (*tls.Config, error) {
	if cfg.InsecureSkipVerify {
		logrus.WithFields(logrus.Fields{
			"component": "mpu_state",
			"setting":   "VALKEY_TLS_INSECURE_SKIP_VERIFY",
		}).Error("InsecureSkipVerify is ENABLED: TLS certificate verification is disabled for Valkey connections. This is UNSAFE in production and allows MITM attacks.")
	}

	tc := &tls.Config{
		// #nosec G402 — operator opt-in with startup warning
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
	}

	switch cfg.MinVersion {
	case "1.2":
		tc.MinVersion = tls.VersionTLS12
	case "", "1.3":
		tc.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("invalid valkey TLS min_version: %q (must be 1.2 or 1.3)", cfg.MinVersion)
	}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certs in CA file %s", cfg.CAFile)
		}
		tc.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	return tc, nil
}

// Create stores a new UploadState using HSETNX for the meta field (idempotency).

// EncryptState seals a plaintext JSON blob with AES-256-GCM.
// Returns a byte slice in the versioned ciphertext format:
//
//	version(1 byte) || nonce(12 bytes) || ciphertext(...) || tag(16 bytes)
//
// Nonce is crypto/rand 96 bits.
func (s *ValkeyStateStore) EncryptState(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.stateKey)
	if err != nil {
		return nil, fmt.Errorf("mpu: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mpu: new gcm: %w", err)
	}

	nonce := make([]byte, stateEncryptionNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("mpu: random nonce: %w", err)
	}

	// Seal appends to dst[:0] so pre-allocate the full output buffer.
	out := make([]byte, stateEncryptionVersionLen+stateEncryptionNonceLen+len(plaintext)+stateEncryptionTagLen)
	out[0] = stateEncryptionVersionV1
	copy(out[stateEncryptionVersionLen:], nonce)
	gcm.Seal(out[stateEncryptionVersionLen+stateEncryptionNonceLen:stateEncryptionVersionLen+stateEncryptionNonceLen], nonce, plaintext, nil)
	return out, nil
}

// DecryptState opens a ciphertext blob sealed by EncryptState.
// If decryption fails with an AEAD tag error, returns ErrStateDecryptFailed
// so the caller can attempt legacy plaintext fallback.
func (s *ValkeyStateStore) DecryptState(ciphertext []byte) ([]byte, error) {
	minLen := stateEncryptionVersionLen + stateEncryptionNonceLen + stateEncryptionTagLen
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("%w: ciphertext too short (%d bytes, need >= %d)", ErrStateDecryptFailed, len(ciphertext), minLen)
	}

	version := ciphertext[0]
	if version != stateEncryptionVersionV1 {
		return nil, fmt.Errorf("%w: unknown version byte 0x%02x", ErrStateDecryptFailed, version)
	}

	block, err := aes.NewCipher(s.stateKey)
	if err != nil {
		return nil, fmt.Errorf("mpu: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mpu: new gcm: %w", err)
	}

	nonce := ciphertext[stateEncryptionVersionLen : stateEncryptionVersionLen+stateEncryptionNonceLen]
	encData := ciphertext[stateEncryptionVersionLen+stateEncryptionNonceLen:]

	plaintext, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateDecryptFailed, err)
	}
	return plaintext, nil
}

func (s *ValkeyStateStore) Create(ctx context.Context, state *UploadState) error {
	key := uploadKey(state.UploadID)
	metaJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("mpu: marshal state: %w", err)
	}

	value := metaJSON
	if s.encryptState {
		encrypted, err := s.EncryptState(metaJSON)
		if err != nil {
			return fmt.Errorf("mpu: encrypt state: %w", err)
		}
		value = encrypted
		s.metrics.IncMPUStateEncryptedWrites("create")
	}

	pipe := s.client.TxPipeline()
	hsetnx := pipe.HSetNX(ctx, key, fieldMeta, value)
	pipe.Expire(ctx, key, s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return wrapRedisErr(err)
	}

	// HSETNX returns false when the key already exists.
	if !hsetnx.Val() {
		return ErrUploadAlreadyExists
	}
	// V1.0-OBS-1 G7: increment active MPU upload gauge on successful create.
	s.metrics.IncMPUActiveUploads()
	return nil
}

// Get retrieves UploadState and all part records.
func (s *ValkeyStateStore) Get(ctx context.Context, uploadID string) (*UploadState, error) {
	key := uploadKey(uploadID)
	fields, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, wrapRedisErr(err)
	}
	if len(fields) == 0 {
		return nil, ErrUploadNotFound
	}

	metaRaw, ok := fields[fieldMeta]
	if !ok {
		return nil, fmt.Errorf("mpu: state record for %q missing meta field", uploadID)
	}

	metaBytes := []byte(metaRaw)
	if s.encryptState {
		decrypted, err := s.DecryptState(metaBytes)
		if err != nil {
			// Decryption failed — try legacy plaintext fallback.
			s.legacyWarn.Do(func() {
				logrus.WithFields(logrus.Fields{
					"component": "mpu_state",
				}).Warn("Unencrypted Valkey state detected — enable valkey.encrypt_state=true")
			})
			s.metrics.IncMPUStateLegacyReads()
			// Leave metaBytes as the raw value; unmarshal below will handle plaintext JSON.
		} else {
			metaBytes = decrypted
			s.metrics.IncMPUStateEncryptedWrites("get")
		}
	}

	var state UploadState
	if err := json.Unmarshal(metaBytes, &state); err != nil {
		return nil, fmt.Errorf("mpu: unmarshal state: %w", err)
	}

	// Reconstruct part records from individual hash fields.
	for k, v := range fields {
		if len(k) <= len(fieldPartPrefix) || k[:len(fieldPartPrefix)] != fieldPartPrefix {
			continue
		}
		var pr PartRecord
		if err := json.Unmarshal([]byte(v), &pr); err != nil {
			return nil, fmt.Errorf("mpu: unmarshal part record %q: %w", k, err)
		}
		state.Parts = append(state.Parts, pr)
	}

	return &state, nil
}

// AppendPart adds a PartRecord and refreshes the TTL.
func (s *ValkeyStateStore) AppendPart(ctx context.Context, uploadID string, part PartRecord) error {
	key := uploadKey(uploadID)

	// Verify key exists before appending.
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return wrapRedisErr(err)
	}
	if exists == 0 {
		return ErrUploadNotFound
	}

	partJSON, err := json.Marshal(part)
	if err != nil {
		return fmt.Errorf("mpu: marshal part record: %w", err)
	}

	fieldName := fmt.Sprintf("%s%d", fieldPartPrefix, part.PartNumber)
	pipe := s.client.Pipeline()
	pipe.HSet(ctx, key, fieldName, partJSON)
	pipe.Expire(ctx, key, s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return wrapRedisErr(err)
	}
	return nil
}

// Delete removes the upload state.
func (s *ValkeyStateStore) Delete(ctx context.Context, uploadID string) error {
	key := uploadKey(uploadID)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return wrapRedisErr(err)
	}
	// V1.0-OBS-1 G7: decrement active MPU upload gauge on successful delete.
	s.metrics.DecMPUActiveUploads()
	return nil
}

// List uses SCAN to find all mpu:* keys and retrieves their UploadState.
func (s *ValkeyStateStore) List(ctx context.Context) ([]UploadState, error) {
	var states []UploadState
	iter := s.client.Scan(ctx, 0, "mpu:*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		metaRaw, err := s.client.HGet(ctx, key, fieldMeta).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, wrapRedisErr(err)
		}

		metaBytes := []byte(metaRaw)
		if s.encryptState {
			decrypted, err := s.DecryptState(metaBytes)
			if err != nil {
				// Legacy plaintext fallback.
				s.legacyWarn.Do(func() {
					logrus.WithFields(logrus.Fields{
						"component": "mpu_state",
					}).Warn("Unencrypted Valkey state detected — enable valkey.encrypt_state=true")
				})
				s.metrics.IncMPUStateLegacyReads()
			} else {
				metaBytes = decrypted
				s.metrics.IncMPUStateEncryptedWrites("list")
			}
		}

		var state UploadState
		if err := json.Unmarshal(metaBytes, &state); err != nil {
			return nil, fmt.Errorf("mpu: unmarshal state for key %s: %w", key, err)
		}
		states = append(states, state)
	}
	if err := iter.Err(); err != nil {
		return nil, wrapRedisErr(err)
	}
	return states, nil
}

// HealthCheck pings Valkey with a 1-second timeout.
func (s *ValkeyStateStore) HealthCheck(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := s.client.Ping(hctx).Err(); err != nil {
		return fmt.Errorf("%w: ping: %v", ErrStateUnavailable, err)
	}
	return nil
}

// Close closes the underlying Redis client and zeroizes sensitive key material.
func (s *ValkeyStateStore) Close() error {
	if s.stateKey != nil {
		zeroBytes(s.stateKey)
		s.stateKey = nil
	}
	return s.client.Close()
}

// wrapRedisErr converts redis-level errors into domain sentinel errors.
func wrapRedisErr(err error) error {
	if errors.Is(err, redis.Nil) {
		return ErrUploadNotFound
	}
	return fmt.Errorf("%w: %v", ErrStateUnavailable, err)
}

// IVPrefixFromHex decodes a hex-encoded IV prefix string back to a [12]byte.
func IVPrefixFromHex(h string) ([12]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return [12]byte{}, err
	}
	if len(b) != 12 {
		return [12]byte{}, fmt.Errorf("mpu: iv prefix must be 12 bytes, got %d", len(b))
	}
	var out [12]byte
	copy(out[:], b)
	return out, nil
}

// UploadIDHashB64 returns the base64url-encoded sha256(uploadID) for storage
// in the finalization manifest (mirrors crypto.UploadIDHash but returns base64).
func UploadIDHashB64(uploadID string) string {
	h := sha256.Sum256([]byte(uploadID))
	return base64.URLEncoding.EncodeToString(h[:])
}

// deriveStateAEADKey derives a dedicated 32-byte AES-256 key from the configured
// password using HKDF-SHA256 Extract. The salt is a fixed public string that is
// distinct from any salt used elsewhere in the binary.
func deriveStateAEADKey(password string) []byte {
	// HKDF-Extract is sufficient here because the input (password) is already
	// a high-entropy secret. A fixed salt is safe as long as it is unique
	// relative to other salts used in the same binary; "s3eg-mpu-state-v1" is
	// distinct from any salt used in the engine's KDF or IV derivation.
	salt := []byte("s3eg-mpu-state-v1")
	// Use HKDF Extract to derive a 32-byte key.
	extracted := hkdf.Extract(sha256.New, []byte(password), salt)
	// hkdf.Extract returns a []byte whose length equals the hash output (32 for SHA-256).
	// Copy it to guarantee immutability of the returned slice.
	key := make([]byte, 32)
	copy(key, extracted)
	return key
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
