package crypto

import (
	"context"
	"errors"
	"time"
)

// KeyManager abstracts an external Key Management System that wraps/unwraps
// per-object Data Encryption Keys (DEKs).
//
// Invariants (MUST hold for every implementation):
//  1. All methods are safe for concurrent use by multiple goroutines.
//  2. ctx is honoured: implementations MUST use ctx for any blocking I/O
//     and return ctx.Err() wrapped when cancellation occurs.
//  3. Plaintext DEKs returned by UnwrapKey MUST be owned by the caller; the
//     caller is responsible for zeroization. Implementations MUST NOT retain
//     a reference to the returned slice. Implementations SHOULD zeroize any
//     internal copies before returning.
//  4. WrapKey MUST NOT log or export plaintext input.
//  5. Close is idempotent; subsequent calls return nil. After Close, all
//     other methods MUST return ErrProviderUnavailable.
//  6. A nil KeyManager is never valid; callers must check.
type KeyManager interface {
	// Provider returns a short identifier (e.g. "cosmian-kmip") used for
	// diagnostics and metadata.
	Provider() string

	// WrapKey encrypts the provided plaintext DEK and returns an envelope
	// suitable for persisting alongside the encrypted object metadata.
	// metadata is advisory context only. Providers may ignore it; callers MUST
	// not rely on it for bucket, key, or object-location integrity. Payload AEAD
	// ObjectContext binding enforces that integrity independently.
	WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error)

	// UnwrapKey decrypts the ciphertext contained in the given envelope and
	// returns the plaintext DEK. The returned slice is owned by the caller,
	// who must zeroize it when done. metadata is advisory context only and
	// providers may ignore it; it MUST NOT be used as the object-location
	// integrity boundary. Payload AEAD ObjectContext binding is enforced
	// independently of the configured KeyManager.
	UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error)

	// ActiveKeyVersion returns the version identifier of the primary wrapping key.
	ActiveKeyVersion(ctx context.Context) (int, error)

	// HealthCheck verifies that the KMS is accessible and operational.
	// Returns an error if the KMS is unavailable or unhealthy.
	// This should be a lightweight operation that does not perform actual
	// encryption/decryption.
	HealthCheck(ctx context.Context) error

	// Close releases any underlying resources. Idempotent: subsequent calls
	// return nil. After Close, all other methods return ErrProviderUnavailable.
	Close(ctx context.Context) error
}

// Sentinel errors for use with errors.Is.
var (
	// ErrProviderUnavailable is returned when the KMS provider is closed or
	// otherwise not operational.
	ErrProviderUnavailable = errors.New("keymanager: provider unavailable")

	// ErrKeyNotFound is returned when the referenced key ID / version does not
	// exist in the KMS.
	ErrKeyNotFound = errors.New("keymanager: key not found")

	// ErrUnwrapFailed is returned when the KMS rejects the ciphertext during
	// an UnwrapKey call (wrong key, corrupted envelope, etc.).
	ErrUnwrapFailed = errors.New("keymanager: unwrap failed")

	// ErrInvalidEnvelope is returned when the supplied KeyEnvelope is
	// structurally invalid (nil, empty ciphertext, missing fields).
	ErrInvalidEnvelope = errors.New("keymanager: invalid envelope")
)

// KeyEnvelope captures the information required to unwrap a DEK.
type KeyEnvelope struct {
	KeyID      string
	KeyVersion int
	Provider   string
	Ciphertext []byte
	// CreatedAt records when the DEK was wrapped. Zero value is safe for
	// backward-compatibility with envelopes that pre-date this field.
	CreatedAt time.Time
}

// MetaKeyVersion is stored on each object to record which wrapping key protected the DEK.
const (
	MetaKeyVersion = "x-amz-meta-encryption-key-version"
)

// RotatableKeyManager is an optional extension implemented by adapters that
// support runtime rotation. Adapters that cannot rotate (e.g. current HSM
// stub) intentionally do not implement it; callers type-assert and return
// ErrRotationNotSupported otherwise.
type RotatableKeyManager interface {
	KeyManager

	// PrepareRotation returns the adapter's view of the rotation target.
	// If target is non-nil, the adapter validates and uses the specified
	// version. If nil, the adapter picks the next eligible version.
	// Returns ErrRotationAmbiguous if the adapter can't choose without
	// operator input (target must then be supplied).
	PrepareRotation(ctx context.Context, target *int) (RotationPlan, error)

	// PromoteActiveVersion atomically advances the adapter's active wrapping
	// key to the previously-prepared target. Must be safe to call concurrently
	// with WrapKey/UnwrapKey: callers that started before Promote observe old
	// version; callers that started after observe new. No ciphertext is
	// rewritten.
	PromoteActiveVersion(ctx context.Context, plan RotationPlan) error
}

// RotationPlan describes a pending key rotation.
type RotationPlan struct {
	CurrentVersion int
	TargetVersion  int
	ProviderData   map[string]string // opaque adapter-specific hints
}

// Sentinel errors for rotation.
var (
	// ErrRotationNotSupported is returned when the configured KeyManager does
	// not implement RotatableKeyManager.
	ErrRotationNotSupported = errors.New("keymanager: key rotation not supported by adapter")

	// ErrRotationAmbiguous is returned by PrepareRotation when the adapter
	// cannot automatically determine the target version.
	ErrRotationAmbiguous = errors.New("keymanager: target_version required for this adapter")

	// ErrRotationConflict is returned when a rotation is already in progress
	// or the state machine is in an invalid state for the requested operation.
	ErrRotationConflict = errors.New("keymanager: rotation already in progress or invalid state")
)
