// Package mpu implements the encrypted multipart upload state store.
// It provides persistence for per-upload encryption state (DEK, IV prefix,
// per-part records) using Valkey (Redis-compatible) as the backend.
package mpu

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
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
	ErrPartContentMismatch = errors.New("mpu: part content differs from immutable claim")
	ErrPartInProgress      = errors.New("mpu: part reservation is in progress")
	ErrInvalidStateVersion = errors.New("mpu: unsupported in-flight state version")
	ErrInvalidPhase        = errors.New("mpu: upload is not open")
	ErrRevisionConflict    = errors.New("mpu: state revision changed")
	ErrCompleteMismatch    = errors.New("mpu: selected parts or etags do not match committed state")
)

const CurrentStateVersion uint8 = 2

type UploadPhase string

const (
	UploadPhaseOpen       UploadPhase = "open"
	UploadPhaseCompleting UploadPhase = "completing"
	UploadPhaseCompleted  UploadPhase = "completed"
	UploadPhaseAborting   UploadPhase = "aborting"
	UploadPhaseAborted    UploadPhase = "aborted"
)

type PartStatus string

const (
	PartStatusReserved  PartStatus = "reserved"
	PartStatusCommitted PartStatus = "committed"
)

// Versioned ciphertext format for at-rest encryption of state blobs.
// Layout: version(1 byte) || nonce(12 bytes) || ciphertext(...) || tag(16 bytes)
const (
	stateEncryptionVersionLen      = 1
	stateEncryptionNonceLen        = 12
	stateEncryptionTagLen          = 16
	stateEncryptionVersionV1  byte = 0x01
)

// PartRecord holds per-part encryption metadata persisted in Valkey.
type PartRecord struct {
	PartNumber int32      `json:"pn"`
	ETag       string     `json:"etag"`
	PlainLen   int64      `json:"plain_len"`
	EncLen     int64      `json:"enc_len"`
	ChunkCount int32      `json:"chunks"`
	Claim      string     `json:"claim,omitempty"`
	Status     PartStatus `json:"status,omitempty"`
	Token      string     `json:"token,omitempty"`
}

type PartClaim struct {
	PartNumber int32      `json:"pn"`
	Claim      string     `json:"claim"`
	PlainLen   int64      `json:"plain_len"`
	Status     PartStatus `json:"status"`
	Token      string     `json:"token"`
	ETag       string     `json:"etag,omitempty"`
	EncLen     int64      `json:"enc_len,omitempty"`
	ChunkCount int32      `json:"chunks,omitempty"`
}

type Reservation struct {
	Token         string
	Revision      uint64
	CommittedETag string
	AlreadyDone   bool
}

type SelectedPart struct {
	PartNumber int32  `json:"pn"`
	ETag       string `json:"etag"`
}

// UploadState holds the encryption state for an in-flight multipart upload.
type UploadState struct {
	UploadID string `json:"upload_id"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	// UploadIDHash is hex(sha256(uploadID)) — stored so IVs can be reconstructed
	// during decryption without re-querying the state.
	UploadIDHash string `json:"uid_hash"`
	// WrappedDEK is the JSON-serialised KeyEnvelope from the KeyManager.
	WrappedDEK string `json:"wrapped_dek"`
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
	StateVersion   uint8          `json:"state_version"`
	Phase          UploadPhase    `json:"phase"`
	Revision       uint64         `json:"revision"`
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

// ClaimStateStore is the nonce-safe protocol implemented by version-2 stores.
// It is separate from StateStore during the rollout so administrative and
// legacy test stores can remain read/delete capable without accepting writes.
type ClaimStateStore interface {
	StateStore
	ReservePart(context.Context, string, PartClaim) (Reservation, error)
	ReleasePart(context.Context, string, int32, string) error
	CommitPart(context.Context, string, PartClaim) error
	BeginComplete(context.Context, string, []SelectedPart) (*UploadState, uint64, error)
	Reopen(context.Context, string, uint64) error
	FinalizeComplete(context.Context, string, uint64) error
	BeginAbort(context.Context, string) (uint64, error)
	FinalizeAbort(context.Context, string, uint64) error
}

const reservePartScript = `
local meta = redis.call('HGET', KEYS[1], 'meta')
if not meta then return {0} end
local version = redis.call('HGET', KEYS[1], 'state_version')
if version ~= '2' then return {1} end
local phase = redis.call('HGET', KEYS[1], 'phase')
if phase ~= 'open' then return {2} end
local field = 'part:' .. ARGV[1]
local current = redis.call('HGET', KEYS[1], field)
if current then
  local decoded = cjson.decode(current)
  local claim = decoded.claim
  local status = decoded.status
  local etag = decoded.etag or ''
  if claim ~= ARGV[2] then return {3} end
  if status == 'reserved' then return {4} end
  if status == 'committed' then return {5, etag} end
end
local revision = tonumber(redis.call('HGET', KEYS[1], 'revision') or '1') + 1
local value = cjson.encode({pn=tonumber(ARGV[1]), claim=ARGV[2], plain_len=tonumber(ARGV[3]), status='reserved', token=ARGV[4]})
redis.call('HSET', KEYS[1], field, value, 'revision', revision)
redis.call('EXPIRE', KEYS[1], ARGV[5])
return {6, revision}
`

const commitPartScript = `
local field = 'part:' .. ARGV[1]
local current = redis.call('HGET', KEYS[1], field)
if not current then return 0 end
local decoded = cjson.decode(current)
local claim = decoded.claim
local token = decoded.token
local status = decoded.status
if claim ~= ARGV[2] or token ~= ARGV[3] then return 2 end
if status == 'committed' then return 1 end
if status ~= 'reserved' then return 2 end
local value = cjson.encode({pn=tonumber(ARGV[1]), claim=ARGV[2], plain_len=tonumber(ARGV[4]), status='committed', token=ARGV[3], etag=ARGV[5], enc_len=tonumber(ARGV[6]), chunks=tonumber(ARGV[7])})
local revision = tonumber(redis.call('HGET', KEYS[1], 'revision') or '1') + 1
redis.call('HSET', KEYS[1], field, value, 'revision', revision)
redis.call('EXPIRE', KEYS[1], ARGV[8])
return 1
`

const releasePartScript = `
local field = 'part:' .. ARGV[1]
local current = redis.call('HGET', KEYS[1], field)
if not current then return 0 end
local decoded = cjson.decode(current)
local token = decoded.token
local status = decoded.status
if status ~= 'reserved' or token ~= ARGV[2] then return 2 end
redis.call('HDEL', KEYS[1], field)
return 1
`

// uploadKey returns the Valkey hash key for an upload: mpu:<hex(sha256(uploadID))>.
func uploadKey(uploadID string) string {
	h := sha256.Sum256([]byte(uploadID))
	return "mpu:" + hex.EncodeToString(h[:])
}

const (
	fieldMeta         = "meta"
	fieldPartPrefix   = "part:"
	fieldStateVersion = "state_version"
	fieldPhase        = "phase"
	fieldRevision     = "revision"
)

// ValkeyStateStore implements StateStore backed by Valkey (via go-redis/v9).
type ValkeyStateStore struct {
	client       redis.UniversalClient
	ttl          time.Duration
	stateDEK     []byte            // random 32-byte AES-256 key (envelope DEK)
	stateKeyV1   []byte            // legacy HKDF key for pre-upgrade state (nil if none)
	keyManager   crypto.KeyManager // wraps/unwraps the state DEK
	encryptState bool
	// allowLegacyPlaintext permits Get/List to fall back to plaintext JSON
	// when state AEAD decryption fails. Intended ONLY for one-time migration
	// from a pre-encryption deployment. Default false (fail-closed). V1.0-SEC-30.
	allowLegacyPlaintext bool
	legacyWarn           sync.Once
	// metrics is optional; when non-nil, encryption counters are reported.
	metrics *metrics.Metrics
}

// NewValkeyStateStore constructs a ValkeyStateStore.
//
// keyManager is required when encryptState is true (fail-closed if nil).
// It wraps/unwraps the random state DEK (envelope pattern). See V1.0-SEC-30.
//
// legacyPassword is used ONLY to derive the V1 HKDF key for backward-compatible
// decrypt of pre-V1.0-SEC-30 state. Pass "" for brand-new deployments with no
// legacy state. The V1 key is read-only (never used for new encryption) and
// expires with the 7-day state TTL.
func NewValkeyStateStore(ctx context.Context, cfg config.ValkeyConfig, keyManager crypto.KeyManager, legacyPassword string) (*ValkeyStateStore, error) {
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

	encryptState := cfg.EncryptState == nil || *cfg.EncryptState
	var stateDEK []byte
	var stateKeyV1 []byte
	var dekErr error

	if encryptState {
		// Fail-closed: require a non-nil KeyManager.
		if keyManager == nil {
			_ = client.Close()
			return nil, fmt.Errorf("%w: state encryption enabled but no KeyManager configured (enable key_manager or set encrypt_state=false)", ErrStateUnavailable)
		}

		// Load or generate the wrapped state DEK.
		stateDEK, dekErr = loadOrGenerateStateDEK(ctx, client, keyManager)
		if dekErr != nil {
			_ = client.Close()
			return nil, fmt.Errorf("mpu: state DEK setup: %w", dekErr)
		}

		// Derive V1 legacy key for backward-compatible decrypt (read-only).
		if legacyPassword != "" {
			stateKeyV1 = deriveStateAEADKeyV1(legacyPassword)
			logrus.WithFields(logrus.Fields{
				"component": "mpu_state",
			}).Debug("V1 legacy state key derived for backward-compatible decrypt (expires with 7-day state TTL)")
		}
	}

	s := &ValkeyStateStore{
		client:               client,
		ttl:                  ttl,
		stateDEK:             stateDEK,
		stateKeyV1:           stateKeyV1,
		keyManager:           keyManager,
		encryptState:         encryptState,
		allowLegacyPlaintext: cfg.AllowLegacyPlaintextState,
	}

	if s.allowLegacyPlaintext {
		logrus.WithFields(logrus.Fields{
			"component": "mpu_state",
		}).Warn("allow_legacy_plaintext_state is true — state decryption will fall back to plaintext on AEAD failure; disable after migration")
	}

	// Fail-closed: if Valkey is unreachable at startup, refuse to start.
	if err := s.HealthCheck(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("%w: %v", ErrStateUnavailable, err)
	}
	return s, nil
}

// stateKeyWrappedKey is the Valkey key for the wrapped state DEK.
const stateKeyWrappedKey = "mpu:state-key-wrapped"

// loadOrGenerateStateDEK loads an existing wrapped state DEK from Valkey, or
// generates a new random 32-byte DEK, wraps it via keyManager, and persists
// the wrapped envelope using SET NX (atomic first-writer-wins across replicas).
func loadOrGenerateStateDEK(ctx context.Context, client redis.UniversalClient, keyManager crypto.KeyManager) ([]byte, error) {
	// Try to load an existing wrapped state DEK.
	wrappedJSON, err := client.Get(ctx, stateKeyWrappedKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("get wrapped state DEK: %w", err)
	}

	if err == nil && wrappedJSON != "" {
		// Load existing: JSON-decode and unwrap.
		var envelope crypto.KeyEnvelope
		if err := json.Unmarshal([]byte(wrappedJSON), &envelope); err != nil {
			return nil, fmt.Errorf("unmarshal wrapped state DEK envelope: %w", err)
		}
		dek, err := keyManager.UnwrapKey(ctx, &envelope, nil)
		if err != nil {
			return nil, fmt.Errorf("unwrap state DEK: %w", err)
		}
		logrus.WithFields(logrus.Fields{
			"component": "mpu_state",
			"provider":  keyManager.Provider(),
		}).Info("unwrapped state DEK via KeyManager")
		return dek, nil
	}

	// Generate new random 32-byte state DEK.
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate state DEK: %w", err)
	}

	envelope, err := keyManager.WrapKey(ctx, dek, nil)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("wrap state DEK: %w", err)
	}

	envJSON, err := json.Marshal(envelope)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("marshal wrapped state DEK envelope: %w", err)
	}

	// Persist with SET NX — atomic first-writer-wins across replicas.
	set, err := client.SetNX(ctx, stateKeyWrappedKey, string(envJSON), 0).Result()
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("persist wrapped state DEK: %w", err)
	}
	if !set {
		// Lost the race — another replica already stored it. Load theirs.
		wrappedJSON, err := client.Get(ctx, stateKeyWrappedKey).Result()
		if err != nil {
			zeroBytes(dek)
			return nil, fmt.Errorf("get wrapped state DEK after race: %w", err)
		}
		var envelope crypto.KeyEnvelope
		if err := json.Unmarshal([]byte(wrappedJSON), &envelope); err != nil {
			zeroBytes(dek)
			return nil, fmt.Errorf("unmarshal wrapped state DEK envelope after race: %w", err)
		}
		dek2, err := keyManager.UnwrapKey(ctx, &envelope, nil)
		if err != nil {
			zeroBytes(dek)
			return nil, fmt.Errorf("unwrap state DEK after race: %w", err)
		}
		zeroBytes(dek) // discard our generated key
		logrus.WithFields(logrus.Fields{
			"component": "mpu_state",
			"provider":  keyManager.Provider(),
		}).Info("unwrapped state DEK via KeyManager (lost SET NX race)")
		return dek2, nil
	}

	logrus.WithFields(logrus.Fields{
		"component": "mpu_state",
		"provider":  keyManager.Provider(),
	}).Info("generated and wrapped new state DEK via KeyManager")
	return dek, nil
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
	block, err := aes.NewCipher(s.stateDEK)
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
// It tries the envelope state DEK first, then the legacy V1 HKDF key (if
// present) for backward-compatible decrypt of pre-upgrade state. Both paths
// return ErrStateDecryptFailed on failure; neither ever falls back to
// plaintext (that is gated by allowLegacyPlaintext at the Get/List call
// sites, not inside DecryptState). V1.0-SEC-30.
func (s *ValkeyStateStore) DecryptState(ciphertext []byte) ([]byte, error) {
	minLen := stateEncryptionVersionLen + stateEncryptionNonceLen + stateEncryptionTagLen
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("%w: ciphertext too short (%d bytes, need >= %d)", ErrStateDecryptFailed, len(ciphertext), minLen)
	}

	version := ciphertext[0]
	if version != stateEncryptionVersionV1 {
		return nil, fmt.Errorf("%w: unknown version byte 0x%02x", ErrStateDecryptFailed, version)
	}

	// Try the envelope state DEK first.
	if s.stateDEK != nil {
		if pt, err := tryOpen(s.stateDEK, ciphertext); err == nil {
			return pt, nil
		}
	}

	// Try the legacy V1 key (if present) for backward-compatible decrypt.
	if s.stateKeyV1 != nil {
		if pt, err := tryOpen(s.stateKeyV1, ciphertext); err == nil {
			return pt, nil
		}
	}

	return nil, fmt.Errorf("%w: aead open failed for all configured keys", ErrStateDecryptFailed)
}

func (s *ValkeyStateStore) Create(ctx context.Context, state *UploadState) error {
	if state == nil {
		return fmt.Errorf("mpu: nil upload state")
	}
	if state.StateVersion == 0 {
		state.StateVersion = CurrentStateVersion
	}
	if state.Phase == "" {
		state.Phase = UploadPhaseOpen
	}
	if state.Revision == 0 {
		state.Revision = 1
	}
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

	hsetnx, err := s.client.HSetNX(ctx, key, fieldMeta, value).Result()
	if err != nil {
		return wrapRedisErr(err)
	}

	// HSETNX returns false when the key already exists.
	if !hsetnx {
		return ErrUploadAlreadyExists
	}
	if err := s.client.HSet(ctx, key, fieldStateVersion, state.StateVersion, fieldPhase, string(state.Phase), fieldRevision, state.Revision).Err(); err != nil {
		return wrapRedisErr(err)
	}
	if err := s.client.Expire(ctx, key, s.ttl).Err(); err != nil {
		return wrapRedisErr(err)
	}
	// V1.0-OBS-1 G7: increment active MPU upload gauge on successful create.
	s.metrics.IncMPUActiveUploads()
	return nil
}

// ComputePartClaim returns the keyed, domain-separated commitment for a part's
// exact plaintext. The reader is bounded by the caller's existing MPU limits.
func ComputePartClaim(dek []byte, partNumber int32, plainLen int64, r io.Reader) ([32]byte, error) {
	var out [32]byte
	if len(dek) == 0 || r == nil || partNumber < 1 || partNumber > 10000 || plainLen < 0 {
		return out, fmt.Errorf("mpu: invalid part claim input")
	}
	h := hmac.New(sha256.New, dek)
	if _, err := h.Write([]byte("s3eg:mpu-part-claim:v1\x00")); err != nil {
		return out, err
	}
	var encoded [12]byte
	binary.BigEndian.PutUint32(encoded[:4], uint32(partNumber))
	binary.BigEndian.PutUint64(encoded[4:], uint64(plainLen))
	if _, err := h.Write(encoded[:]); err != nil {
		return out, err
	}
	count, err := io.Copy(h, io.LimitReader(r, plainLen))
	if err != nil {
		return out, fmt.Errorf("mpu: compute part claim: %w", err)
	}
	if count != plainLen {
		return out, fmt.Errorf("mpu: plaintext length mismatch: got %d, expected %d", count, plainLen)
	}
	return [32]byte(h.Sum(nil)), nil
}

func (s *ValkeyStateStore) ReservePart(ctx context.Context, uploadID string, part PartClaim) (Reservation, error) {
	if part.PartNumber < 1 || part.PartNumber > 10000 || part.Claim == "" || part.Token == "" || part.PlainLen < 0 {
		return Reservation{}, fmt.Errorf("mpu: invalid part claim")
	}
	result, err := s.client.Eval(ctx, reservePartScript, []string{uploadKey(uploadID)}, part.PartNumber, part.Claim, part.PlainLen, part.Token, int(s.ttl/time.Second)).Result()
	if err != nil {
		return Reservation{}, wrapRedisErr(err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) == 0 {
		return Reservation{}, fmt.Errorf("mpu: malformed reserve result")
	}
	code, ok := redisInt(values[0])
	if !ok {
		return Reservation{}, fmt.Errorf("mpu: malformed reserve code")
	}
	switch code {
	case 0:
		return Reservation{}, ErrUploadNotFound
	case 1:
		return Reservation{}, ErrInvalidStateVersion
	case 2:
		return Reservation{}, ErrInvalidPhase
	case 3:
		return Reservation{}, ErrPartContentMismatch
	case 4:
		return Reservation{}, ErrPartInProgress
	case 5:
		var etag string
		if len(values) > 1 {
			etag, _ = values[1].(string)
		}
		return Reservation{CommittedETag: etag, AlreadyDone: true}, nil
	case 6:
		if len(values) < 2 {
			return Reservation{}, fmt.Errorf("mpu: malformed reserve revision")
		}
		revision, ok := redisInt(values[1])
		if !ok {
			return Reservation{}, fmt.Errorf("mpu: malformed reserve revision")
		}
		return Reservation{Token: part.Token, Revision: uint64(revision)}, nil
	default:
		return Reservation{}, fmt.Errorf("mpu: unknown reserve result %d", code)
	}
}

func (s *ValkeyStateStore) CommitPart(ctx context.Context, uploadID string, part PartClaim) error {
	if part.Token == "" || part.Claim == "" {
		return fmt.Errorf("mpu: invalid commit claim")
	}
	result, err := s.client.Eval(ctx, commitPartScript, []string{uploadKey(uploadID)}, part.PartNumber, part.Claim, part.Token, part.PlainLen, part.ETag, part.EncLen, part.ChunkCount, int(s.ttl/time.Second)).Result()
	if err != nil {
		return wrapRedisErr(err)
	}
	code, ok := redisInt(result)
	if !ok {
		return fmt.Errorf("mpu: malformed commit result")
	}
	switch code {
	case 0:
		return ErrUploadNotFound
	case 1:
		return nil
	case 2:
		return ErrRevisionConflict
	default:
		return fmt.Errorf("mpu: unknown commit result %d", code)
	}
}

func (s *ValkeyStateStore) ReleasePart(ctx context.Context, uploadID string, partNumber int32, token string) error {
	if partNumber < 1 || token == "" {
		return fmt.Errorf("mpu: invalid release claim")
	}
	result, err := s.client.Eval(ctx, releasePartScript, []string{uploadKey(uploadID)}, partNumber, token).Result()
	if err != nil {
		return wrapRedisErr(err)
	}
	code, ok := redisInt(result)
	if !ok {
		return fmt.Errorf("mpu: malformed release result")
	}
	if code == 0 {
		return ErrUploadNotFound
	}
	if code != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func (s *ValkeyStateStore) BeginComplete(ctx context.Context, uploadID string, selected []SelectedPart) (*UploadState, uint64, error) {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return nil, 0, err
	}
	if state.StateVersion != CurrentStateVersion {
		return nil, 0, ErrInvalidStateVersion
	}
	if state.Phase != UploadPhaseOpen {
		return nil, 0, ErrInvalidPhase
	}
	if len(selected) == 0 {
		return nil, 0, ErrCompleteMismatch
	}
	parts := make([]PartRecord, 0, len(selected))
	byNumber := make(map[int32]PartRecord, len(state.Parts))
	for _, part := range state.Parts {
		byNumber[part.PartNumber] = part
	}
	var previous int32
	for i, requested := range selected {
		if requested.PartNumber < 1 || requested.PartNumber > 10000 || (i > 0 && requested.PartNumber <= previous) {
			return nil, 0, ErrCompleteMismatch
		}
		part, ok := byNumber[requested.PartNumber]
		if !ok || (part.Status != "" && part.Status != PartStatusCommitted) || !sameETag(part.ETag, requested.ETag) {
			return nil, 0, fmt.Errorf("%w: part=%d found=%t status=%q stored_etag=%q requested_etag=%q", ErrCompleteMismatch, requested.PartNumber, ok, part.Status, part.ETag, requested.ETag)
		}
		parts = append(parts, part)
		previous = requested.PartNumber
	}
	state.Parts = parts
	state.Phase = UploadPhaseCompleting
	state.Revision++
	if err := s.persistControl(ctx, uploadID, state); err != nil {
		return nil, 0, err
	}
	return state, state.Revision, nil
}

func sameETag(a, b string) bool {
	trim := func(value string) string { return strings.Trim(value, "\"") }
	return trim(a) == trim(b)
}

func (s *ValkeyStateStore) Reopen(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	if state.Revision != revision || state.Phase != UploadPhaseCompleting {
		return ErrRevisionConflict
	}
	state.Phase = UploadPhaseOpen
	state.Revision++
	return s.persistControl(ctx, uploadID, state)
}

func (s *ValkeyStateStore) FinalizeComplete(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	if state.Revision != revision || state.Phase != UploadPhaseCompleting {
		return ErrRevisionConflict
	}
	state.Phase = UploadPhaseCompleted
	return s.persistControl(ctx, uploadID, state)
}

func (s *ValkeyStateStore) BeginAbort(ctx context.Context, uploadID string) (uint64, error) {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	if state.StateVersion != 0 && state.StateVersion != CurrentStateVersion {
		return 0, ErrInvalidStateVersion
	}
	if state.Phase != "" && state.Phase != UploadPhaseOpen {
		return 0, ErrInvalidPhase
	}
	state.Phase = UploadPhaseAborting
	state.Revision++
	if err := s.persistControl(ctx, uploadID, state); err != nil {
		return 0, err
	}
	return state.Revision, nil
}

func (s *ValkeyStateStore) FinalizeAbort(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	if state.Revision != revision || state.Phase != UploadPhaseAborting {
		return ErrRevisionConflict
	}
	state.Phase = UploadPhaseAborted
	return s.persistControl(ctx, uploadID, state)
}

func (s *ValkeyStateStore) persistControl(ctx context.Context, uploadID string, state *UploadState) error {
	metaState := *state
	// Part records are durable hash fields; keeping them out of meta avoids
	// duplicating records when Get reconstructs the state.
	metaState.Parts = nil
	meta, err := json.Marshal(&metaState)
	if err != nil {
		return err
	}
	if s.encryptState {
		meta, err = s.EncryptState(meta)
		if err != nil {
			return err
		}
	}
	key := uploadKey(uploadID)
	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, fieldMeta, meta, fieldStateVersion, state.StateVersion, fieldPhase, string(state.Phase), fieldRevision, state.Revision)
	pipe.Expire(ctx, key, s.ttl)
	_, err = pipe.Exec(ctx)
	return wrapRedisErr(err)
}

func redisInt(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
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
	if version, ok := fields[fieldStateVersion]; ok {
		v, err := strconv.ParseUint(version, 10, 8)
		if err != nil || uint8(v) != CurrentStateVersion {
			return nil, ErrInvalidStateVersion
		}
	}

	metaRaw, ok := fields[fieldMeta]
	if !ok {
		return nil, fmt.Errorf("mpu: state record for %q missing meta field", uploadID)
	}

	metaBytes := []byte(metaRaw)
	if s.encryptState {
		decrypted, err := s.DecryptState(metaBytes)
		if err != nil {
			if !s.allowLegacyPlaintext {
				// Fail closed: do NOT treat AEAD failure as plaintext.
				return nil, fmt.Errorf("%w: state decryption failed for upload %q "+
					"(set allow_legacy_plaintext_state=true only if migrating from plaintext)",
					err, uploadID)
			}
			// Legacy plaintext fallback (opt-in migration path).
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
	if state.StateVersion != 0 && state.StateVersion != CurrentStateVersion {
		return nil, ErrInvalidStateVersion
	}
	if mirrored, ok := fields[fieldPhase]; ok && state.Phase != "" && mirrored != string(state.Phase) {
		return nil, fmt.Errorf("mpu: state phase mirror mismatch")
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
	if part.Status == "" {
		part.Status = PartStatusCommitted
	}

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
		// Skip the state DEK wrapper key — it is a plain string, not a hash.
		if key == stateKeyWrappedKey {
			continue
		}
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
				if !s.allowLegacyPlaintext {
					// Fail closed: skip this key.
					continue
				}
				// Legacy plaintext fallback (opt-in migration path).
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
// Client returns the underlying redis.UniversalClient, so callers can share
// the connection pool with other components (e.g. the size cache).
func (s *ValkeyStateStore) Client() redis.UniversalClient {
	return s.client
}

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
	if s.stateDEK != nil {
		zeroBytes(s.stateDEK)
		s.stateDEK = nil
	}
	if s.stateKeyV1 != nil {
		zeroBytes(s.stateKeyV1)
		s.stateKeyV1 = nil
	}
	return s.client.Close()
}

// wrapRedisErr converts redis-level errors into domain sentinel errors.
func wrapRedisErr(err error) error {
	if err == nil {
		return nil
	}
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

// deriveStateAEADKeyV1 derives the legacy V1 32-byte AES-256 key from the
// configured password using HKDF-SHA256 Extract.
//
// Deprecated: retained for backward-compatible decrypt of pre-V1.0-SEC-30
// state during the 7-day state TTL window. New deployments generate a random
// state DEK wrapped by the KeyManager instead (see NewValkeyStateStore).
func deriveStateAEADKeyV1(password string) []byte {
	salt := []byte("s3eg-mpu-state-v1")
	extracted := hkdf.Extract(sha256.New, []byte(password), salt)
	key := make([]byte, 32)
	copy(key, extracted)
	return key
}

// tryOpen tries to open ciphertext with the given key using AES-256-GCM.
// Returns the plaintext on success, or an error on AEAD failure.
func tryOpen(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
