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
	UploadID  string `json:"upload_id"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	BindingID string `json:"binding_id,omitempty"`
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

// BindingIDBytes validates and decodes the persisted v2 binding. Empty means
// an explicitly legacy in-flight upload; malformed non-empty values fail.
func (s *UploadState) BindingIDBytes() ([16]byte, bool, error) {
	var out [16]byte
	if s == nil || s.BindingID == "" {
		return out, false, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s.BindingID)
	if err != nil || len(b) != 16 {
		return out, false, fmt.Errorf("mpu: invalid binding ID")
	}
	copy(out[:], b)
	if out == [16]byte{} {
		return out, false, fmt.Errorf("mpu: zero binding ID")
	}
	return out, true, nil
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

	ReservePart(ctx context.Context, uploadID string, part PartClaim) (Reservation, error)
	ReleasePart(ctx context.Context, uploadID string, partNumber int32, token string) error
	CommitPart(ctx context.Context, uploadID string, part PartClaim) error
	BeginComplete(ctx context.Context, uploadID string, selected []SelectedPart) (*UploadState, uint64, error)
	Reopen(ctx context.Context, uploadID string, revision uint64) error
	FinalizeComplete(ctx context.Context, uploadID string, revision uint64) error
	BeginAbort(ctx context.Context, uploadID string) (uint64, error)
	FinalizeAbort(ctx context.Context, uploadID string, revision uint64) error

	// Delete removes the upload state. Safe to call on missing keys.
	Delete(ctx context.Context, uploadID string) error

	// List returns all active multipart uploads by scanning the store.
	List(ctx context.Context) ([]UploadState, error)

	// HealthCheck performs a lightweight liveness check against Valkey.
	HealthCheck(ctx context.Context) error

	// Close releases resources. Idempotent.
	Close() error
}

// ClaimStateStore is an alias retained for callers using the claim protocol.
type ClaimStateStore = StateStore

const reservePartScript = `
local meta = redis.call('HGET', KEYS[1], 'meta')
if not meta then return {0} end
local version = redis.call('HGET', KEYS[1], 'state_version')
if version ~= '2' then return {1} end
local phase = redis.call('HGET', KEYS[1], 'phase')
if phase ~= 'open' then return {2} end
if tonumber(redis.call('HGET', KEYS[1], 'revision') or '0') ~= tonumber(ARGV[5]) then return {7} end
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
redis.call('HSET', KEYS[1], field, value, 'meta', ARGV[6], 'revision', revision)
redis.call('EXPIRE', KEYS[1], ARGV[7])
return {6, revision}
`

var reservePartLua = redis.NewScript(reservePartScript)

var runReservePart = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
	return reservePartLua.Run(ctx, client, keys, args...).Result()
}

const commitPartScript = `
local meta = redis.call('HGET', KEYS[1], 'meta')
if not meta then return 0 end
if redis.call('HGET', KEYS[1], 'state_version') ~= '2' then return 3 end
if redis.call('HGET', KEYS[1], 'phase') ~= 'open' then return 4 end
if tonumber(redis.call('HGET', KEYS[1], 'revision') or '0') ~= tonumber(ARGV[8]) then return 5 end
local field = 'part:' .. ARGV[1]
local current = redis.call('HGET', KEYS[1], field)
if not current then return 0 end
local decoded = cjson.decode(current)
local claim = decoded.claim
local token = decoded.token
local status = decoded.status
if claim ~= ARGV[2] or token ~= ARGV[3] then return 2 end
if status == 'committed' then
  if tonumber(decoded.plain_len) ~= tonumber(ARGV[4]) or decoded.etag ~= ARGV[5] or tonumber(decoded.enc_len) ~= tonumber(ARGV[6]) or tonumber(decoded.chunks) ~= tonumber(ARGV[7]) then return 2 end
  return 1
end
if status ~= 'reserved' then return 2 end
local value = cjson.encode({pn=tonumber(ARGV[1]), claim=ARGV[2], plain_len=tonumber(ARGV[4]), status='committed', token=ARGV[3], etag=ARGV[5], enc_len=tonumber(ARGV[6]), chunks=tonumber(ARGV[7])})
local revision = tonumber(redis.call('HGET', KEYS[1], 'revision') or '1') + 1
redis.call('HSET', KEYS[1], field, value, 'meta', ARGV[9], 'revision', revision)
redis.call('EXPIRE', KEYS[1], ARGV[10])
return 1
`

var commitPartLua = redis.NewScript(commitPartScript)

var runCommitPart = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
	return commitPartLua.Run(ctx, client, keys, args...).Result()
}

const createStateScript = `
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'meta', ARGV[1], 'state_version', '2', 'phase', 'open', 'revision', '1')
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
`

var createStateLua = redis.NewScript(createStateScript)

const releasePartScript = `
if redis.call('HGET', KEYS[1], 'state_version') ~= '2' then return 3 end
if redis.call('HGET', KEYS[1], 'phase') ~= 'open' then return 4 end
if tonumber(redis.call('HGET', KEYS[1], 'revision') or '0') ~= tonumber(ARGV[3]) then return 5 end
local field = 'part:' .. ARGV[1]
local current = redis.call('HGET', KEYS[1], field)
if not current then return 0 end
local decoded = cjson.decode(current)
local token = decoded.token
local status = decoded.status
if status ~= 'reserved' or token ~= ARGV[2] then return 2 end
redis.call('HDEL', KEYS[1], field)
redis.call('HSET', KEYS[1], 'meta', ARGV[4], 'revision', tonumber(ARGV[3]) + 1)
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
`

var releasePartLua = redis.NewScript(releasePartScript)

var runReleasePart = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
	return releasePartLua.Run(ctx, client, keys, args...).Result()
}

const atomicLifecycleScript = `
local current = redis.call('HGET', KEYS[1], 'meta')
if not current then return 0 end
local version = redis.call('HGET', KEYS[1], 'state_version')
if version ~= '2' and ARGV[5] ~= 'allow_legacy_abort' then return 1 end
local currentPhase = redis.call('HGET', KEYS[1], 'phase')
local currentRevision = redis.call('HGET', KEYS[1], 'revision')
if ARGV[5] == 'allow_legacy_abort' and not currentPhase and not currentRevision then
  if ARGV[1] ~= 'open' or tonumber(ARGV[2]) ~= 0 then return 3 end
else
  if currentPhase ~= ARGV[1] then return 2 end
  if tonumber(currentRevision or '0') ~= tonumber(ARGV[2]) then return 3 end
end
redis.call('HSET', KEYS[1], 'meta', ARGV[4], 'state_version', '2', 'phase', ARGV[3], 'revision', tonumber(ARGV[2]) + 1)
redis.call('EXPIRE', KEYS[1], ARGV[6])
return 4
`

var atomicLifecycleLua = redis.NewScript(atomicLifecycleScript)

var runAtomicLifecycle = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
	return atomicLifecycleLua.Run(ctx, client, keys, args...).Result()
}

// beginCompleteScript validates the selected part set while holding Valkey's
// single-threaded Lua execution lock. Control fields are the authoritative
// non-secret state; encrypted meta is immutable after Create and Get overlays
// these fields after authenticated decryption.
const beginCompleteScript = `
local meta = redis.call('HGET', KEYS[1], 'meta')
if not meta then return {0} end
if redis.call('HGET', KEYS[1], 'state_version') ~= '2' then return {1} end
if redis.call('HGET', KEYS[1], 'phase') ~= 'open' then return {2} end
if tonumber(redis.call('HGET', KEYS[1], 'revision') or '0') ~= tonumber(ARGV[1]) then return {3} end
local out = {4}
local previous = 0
for i = 2, #ARGV - 2, 2 do
  local pn = tonumber(ARGV[i])
  local wanted = ARGV[i + 1]
  if not pn or pn < 1 or pn > 10000 or pn <= previous then return {5} end
  local raw = redis.call('HGET', KEYS[1], 'part:' .. pn)
  if not raw then return {5} end
  local p = cjson.decode(raw)
  if p.status ~= 'committed' then return {5} end
  local etag = string.gsub(p.etag or '', '^"(.*)"$', '%1')
  local want = string.gsub(wanted, '^"(.*)"$', '%1')
  if etag ~= want then return {5} end
  table.insert(out, raw)
  previous = pn
end
local nextRevision = tonumber(ARGV[1]) + 1
redis.call('HSET', KEYS[1], 'meta', ARGV[#ARGV - 1], 'phase', 'completing', 'revision', nextRevision)
redis.call('EXPIRE', KEYS[1], ARGV[#ARGV])
return out
`

var beginCompleteLua = redis.NewScript(beginCompleteScript)

var runBeginComplete = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
	return beginCompleteLua.Run(ctx, client, keys, args...).Result()
}

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
	// writerCapabilityKey is an operator-controlled activation gate. It must be
	// written only after legacy MPU writers have been drained.
	writerCapabilityKey  = "mpu:writer-version"
	writerPresencePrefix = "mpu:writer:"
	writerPresenceTTL    = 15 * time.Second
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
	metrics          *metrics.Metrics
	writerCapability string
	writerPresenceID string
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
		writerCapability:     cfg.WriterCapability,
		writerPresenceID:     randomWriterPresenceID(),
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
	if _, _, err := state.BindingIDBytes(); err != nil {
		return err
	}
	// Creation is a schema boundary. Do not allow callers to smuggle lifecycle
	// controls into authenticated metadata that the Lua create script replaces.
	state.StateVersion = CurrentStateVersion
	state.Phase = UploadPhaseOpen
	state.Revision = 1
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

	result, err := createStateLua.Run(ctx, s.client, []string{key}, value, int(s.ttl/time.Second)).Result()
	if err != nil {
		return wrapRedisErr(err)
	}
	created, ok := redisInt(result)
	if !ok {
		return fmt.Errorf("mpu: malformed create result")
	}
	if created != 1 {
		return ErrUploadAlreadyExists
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
	for attempts := 0; attempts < 16; attempts++ {
		if err := ctx.Err(); err != nil {
			return Reservation{}, err
		}
		state, err := s.Get(ctx, uploadID)
		if err != nil {
			return Reservation{}, err
		}
		meta, err := s.controlMeta(state, UploadPhaseOpen, state.Revision+1)
		if err != nil {
			return Reservation{}, err
		}
		result, err := runReservePart(ctx, s.client, []string{uploadKey(uploadID)}, part.PartNumber, part.Claim, part.PlainLen, part.Token, state.Revision, meta, int(s.ttl/time.Second))
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
			if revision < 0 {
				return Reservation{}, fmt.Errorf("mpu: invalid reserve revision")
			}
			return Reservation{Token: part.Token, Revision: uint64(revision)}, nil
		case 7:
			continue
		default:
			return Reservation{}, fmt.Errorf("mpu: unknown reserve result %d", code)
		}
	}
	return Reservation{}, ErrRevisionConflict
}

func (s *ValkeyStateStore) CommitPart(ctx context.Context, uploadID string, part PartClaim) error {
	if part.PartNumber < 1 || part.PartNumber > 10000 || part.Token == "" || part.Claim == "" {
		return fmt.Errorf("mpu: invalid commit claim")
	}
	for attempts := 0; attempts < 16; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := s.Get(ctx, uploadID)
		if err != nil {
			return err
		}
		meta, err := s.controlMeta(state, UploadPhaseOpen, state.Revision+1)
		if err != nil {
			return err
		}
		result, err := runCommitPart(ctx, s.client, []string{uploadKey(uploadID)}, part.PartNumber, part.Claim, part.Token, part.PlainLen, part.ETag, part.EncLen, part.ChunkCount, state.Revision, meta, int(s.ttl/time.Second))
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
		case 3:
			return ErrInvalidStateVersion
		case 4:
			return ErrInvalidPhase
		case 5:
			continue
		default:
			return fmt.Errorf("mpu: unknown commit result %d", code)
		}
	}
	return ErrRevisionConflict
}

func (s *ValkeyStateStore) controlMeta(state *UploadState, phase UploadPhase, revision uint64) ([]byte, error) {
	copyState := *state
	copyState.Parts = nil
	copyState.StateVersion = CurrentStateVersion
	copyState.Phase = phase
	copyState.Revision = revision
	meta, err := json.Marshal(&copyState)
	if err != nil {
		return nil, err
	}
	if s.encryptState {
		return s.EncryptState(meta)
	}
	return meta, nil
}

func (s *ValkeyStateStore) ReleasePart(ctx context.Context, uploadID string, partNumber int32, token string) error {
	if partNumber < 1 || token == "" {
		return fmt.Errorf("mpu: invalid release claim")
	}
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	meta, err := s.controlMeta(state, UploadPhaseOpen, state.Revision+1)
	if err != nil {
		return err
	}
	result, err := runReleasePart(ctx, s.client, []string{uploadKey(uploadID)}, partNumber, token, state.Revision, meta, int(s.ttl/time.Second))
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
	if code == 3 {
		return ErrInvalidStateVersion
	}
	if code == 4 {
		return ErrInvalidPhase
	}
	if code == 5 {
		return ErrRevisionConflict
	}
	if code != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func (s *ValkeyStateStore) BeginComplete(ctx context.Context, uploadID string, selected []SelectedPart) (*UploadState, uint64, error) {
	if len(selected) == 0 {
		return nil, 0, ErrCompleteMismatch
	}
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return nil, 0, err
	}
	args := []interface{}{state.Revision}
	for _, p := range selected {
		args = append(args, p.PartNumber, p.ETag)
	}
	meta, err := s.controlMeta(state, UploadPhaseCompleting, state.Revision+1)
	if err != nil {
		return nil, 0, err
	}
	args = append(args, meta, int(s.ttl/time.Second))
	result, err := runBeginComplete(ctx, s.client, []string{uploadKey(uploadID)}, args...)
	if err != nil {
		return nil, 0, wrapRedisErr(err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) == 0 {
		return nil, 0, fmt.Errorf("mpu: malformed complete result")
	}
	code, ok := redisInt(values[0])
	if !ok {
		return nil, 0, fmt.Errorf("mpu: malformed complete code")
	}
	switch code {
	case 0:
		return nil, 0, ErrUploadNotFound
	case 1:
		return nil, 0, ErrInvalidStateVersion
	case 2:
		return nil, 0, ErrInvalidPhase
	case 3:
		return nil, 0, ErrRevisionConflict
	case 5:
		return nil, 0, ErrCompleteMismatch
	case 4:
	default:
		return nil, 0, fmt.Errorf("mpu: unknown complete result %d", code)
	}
	state.Phase, state.Revision = UploadPhaseCompleting, state.Revision+1
	selectedParts := make([]PartRecord, 0, len(values)-1)
	for _, raw := range values[1:] {
		var p PartRecord
		b, ok := raw.(string)
		if !ok || json.Unmarshal([]byte(b), &p) != nil {
			return nil, 0, fmt.Errorf("mpu: malformed selected part")
		}
		selectedParts = append(selectedParts, p)
	}
	state.Parts = selectedParts
	s.recordTransition("open", "completing", "success")
	return state, state.Revision, nil
}

func (s *ValkeyStateStore) Reopen(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	from := state.Phase
	if from != UploadPhaseCompleting && from != UploadPhaseAborting {
		return ErrInvalidPhase
	}
	state.Phase, state.Revision = UploadPhaseOpen, revision+1
	err = s.atomicLifecycle(ctx, uploadID, from, revision, UploadPhaseOpen, state)
	s.recordTransition(string(from), "open", transitionResult(err))
	return err
}

func (s *ValkeyStateStore) FinalizeComplete(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	state.Phase, state.Revision = UploadPhaseCompleted, revision+1
	err = s.atomicLifecycle(ctx, uploadID, UploadPhaseCompleting, revision, UploadPhaseCompleted, state)
	s.recordTransition("completing", "completed", transitionResult(err))
	return err
}

func (s *ValkeyStateStore) BeginAbort(ctx context.Context, uploadID string) (uint64, error) {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	if state.StateVersion != 0 && state.StateVersion != 1 && state.StateVersion != CurrentStateVersion {
		return 0, ErrInvalidStateVersion
	}
	if state.Phase != "" && state.Phase != UploadPhaseOpen {
		return 0, ErrInvalidPhase
	}
	legacy := state.StateVersion != CurrentStateVersion
	from := string(state.Phase)
	if legacy && from == "" {
		from = string(UploadPhaseOpen)
	}
	state.Phase, state.Revision = UploadPhaseAborting, state.Revision+1
	if err := s.atomicLifecycle(ctx, uploadID, UploadPhase(from), state.Revision-1, UploadPhaseAborting, state); err != nil {
		s.recordTransition(from, "aborting", "error")
		return 0, err
	}
	s.recordTransition(from, "aborting", "success")
	return state.Revision, nil
}

func (s *ValkeyStateStore) FinalizeAbort(ctx context.Context, uploadID string, revision uint64) error {
	state, err := s.Get(ctx, uploadID)
	if err != nil {
		return err
	}
	state.Phase, state.Revision = UploadPhaseAborted, revision+1
	err = s.atomicLifecycle(ctx, uploadID, UploadPhaseAborting, revision, UploadPhaseAborted, state)
	s.recordTransition("aborting", "aborted", transitionResult(err))
	return err
}

func (s *ValkeyStateStore) atomicLifecycle(ctx context.Context, uploadID string, from UploadPhase, revision uint64, to UploadPhase, state *UploadState) error {
	metaState := *state
	metaState.Parts = nil
	legacyAbort := to == UploadPhaseAborting && state.StateVersion != CurrentStateVersion
	if legacyAbort {
		// The legacy marker is used only to authorize this abort. Persist the
		// upgraded control/meta state atomically with the transition.
		metaState.StateVersion = CurrentStateVersion
	}
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
	allowLegacy := ""
	if legacyAbort {
		// Legacy aborts are upgraded only as part of the abort transition.
		allowLegacy = "allow_legacy_abort"
	}
	result, err := runAtomicLifecycle(ctx, s.client, []string{uploadKey(uploadID)}, string(from), revision, string(to), meta, allowLegacy, int(s.ttl/time.Second))
	if err != nil {
		return wrapRedisErr(err)
	}
	code, ok := redisInt(result)
	if !ok {
		return fmt.Errorf("mpu: malformed atomic lifecycle result")
	}
	switch code {
	case 0:
		return ErrUploadNotFound
	case 1:
		return ErrInvalidStateVersion
	case 2:
		return ErrInvalidPhase
	case 3:
		return ErrRevisionConflict
	case 4:
		return nil
	default:
		return fmt.Errorf("mpu: unknown atomic lifecycle result %d", code)
	}
}

func transitionResult(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

func (s *ValkeyStateStore) recordTransition(from, to, result string) {
	if s.metrics != nil {
		s.metrics.RecordMPUStateTransition(from, to, result)
	}
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
	// Keep legacy records readable so request handlers can return the
	// actionable abort-only OperationAborted response. Write operations still
	// reject missing/version-1 state in their atomic scripts.

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
	if _, _, err := state.BindingIDBytes(); err != nil {
		return nil, err
	}
	// Legacy state remains readable so handlers can return the abort-only
	// OperationAborted contract. For authenticated non-legacy metadata, every
	// mirrored control field must agree exactly; never overlay an unchecked
	// mirror onto authenticated state.
	if state.StateVersion == CurrentStateVersion && fields[fieldStateVersion] != "" && fields[fieldPhase] != "" && fields[fieldRevision] != "" {
		mirrored, ok := fields[fieldStateVersion]
		v, parseErr := strconv.ParseUint(mirrored, 10, 8)
		if !ok || parseErr != nil || uint8(v) != state.StateVersion {
			return nil, fmt.Errorf("mpu: state version mirror mismatch: %w", ErrInvalidStateVersion)
		}
	}
	if state.Phase != "" {
		mirrored, ok := fields[fieldPhase]
		if !ok || UploadPhase(mirrored) != state.Phase {
			return nil, fmt.Errorf("mpu: state phase mirror mismatch: %w", ErrInvalidPhase)
		}
	}
	if state.Revision != 0 {
		mirrored, ok := fields[fieldRevision]
		v, parseErr := strconv.ParseUint(mirrored, 10, 64)
		if !ok || parseErr != nil || v != state.Revision {
			return nil, fmt.Errorf("mpu: state revision mirror mismatch: %w", ErrRevisionConflict)
		}
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
		if key == writerCapabilityKey {
			continue
		}
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
	legacy := 0
	for _, state := range states {
		if state.StateVersion != CurrentStateVersion {
			legacy++
		}
	}
	if s.metrics != nil {
		s.metrics.SetMPULegacyInflight(float64(legacy))
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

// WriterCapabilityReady verifies the operator-controlled activation gate and
// supplementary new-writer heartbeats. Legacy binaries cannot publish a
// heartbeat, so the gate must remain unset until those writers are drained.
func (s *ValkeyStateStore) WriterCapabilityReady(ctx context.Context) error {
	if s.writerCapability == "" {
		return fmt.Errorf("%w: MPU writer capability is not configured", ErrStateUnavailable)
	}
	version, err := s.client.Get(ctx, writerCapabilityKey).Result()
	if err != nil {
		return wrapRedisErr(err)
	}
	if version != s.writerCapability {
		return fmt.Errorf("%w: MPU writer activation gate is not enabled for this capability", ErrInvalidStateVersion)
	}
	if s.writerPresenceID == "" {
		s.writerPresenceID = randomWriterPresenceID()
	}
	presenceHash := sha256.Sum256([]byte(s.writerPresenceID))
	presenceKey := writerPresencePrefix + hex.EncodeToString(presenceHash[:])
	if err := s.client.Set(ctx, presenceKey, s.writerCapability, writerPresenceTTL).Err(); err != nil {
		return wrapRedisErr(err)
	}
	legacy, err := s.legacyInflightCount(ctx)
	if err != nil {
		return err
	}
	if legacy > 0 {
		return fmt.Errorf("%w: legacy encrypted MPU state remains in flight", ErrInvalidStateVersion)
	}
	iter := s.client.Scan(ctx, 0, writerPresencePrefix+"*", 0).Iterator()
	for iter.Next(ctx) {
		capability, err := s.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			return wrapRedisErr(err)
		}
		if capability != s.writerCapability {
			return fmt.Errorf("%w: incompatible active MPU writer capability", ErrInvalidStateVersion)
		}
	}
	if err := iter.Err(); err != nil {
		return wrapRedisErr(err)
	}
	return nil
}

func randomWriterPresenceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (s *ValkeyStateStore) legacyInflightCount(ctx context.Context) (int, error) {
	legacy := 0
	iter := s.client.Scan(ctx, 0, "mpu:*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		if key == writerCapabilityKey || strings.HasPrefix(key, writerPresencePrefix) || key == stateKeyWrappedKey {
			continue
		}
		fields, err := s.client.HGetAll(ctx, key).Result()
		if err != nil {
			return 0, wrapRedisErr(err)
		}
		if len(fields) == 0 {
			continue
		}
		meta, ok := fields[fieldMeta]
		if !ok {
			return 0, fmt.Errorf("mpu: state record missing meta field")
		}
		data := []byte(meta)
		if s.encryptState {
			decrypted, err := s.DecryptState(data)
			if err != nil {
				if !s.allowLegacyPlaintext {
					return 0, fmt.Errorf("%w: legacy inventory state decryption failed", ErrStateUnavailable)
				}
			} else {
				data = decrypted
			}
		}
		var state UploadState
		if err := json.Unmarshal(data, &state); err != nil {
			return 0, fmt.Errorf("mpu: legacy inventory state decode failed: %w", err)
		}
		if state.PolicySnapshot.EncryptMultipartUploads && state.StateVersion != CurrentStateVersion {
			legacy++
		}
	}
	if err := iter.Err(); err != nil {
		return 0, wrapRedisErr(err)
	}
	if s.metrics != nil {
		s.metrics.SetMPULegacyInflight(float64(legacy))
	}
	return legacy, nil
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
