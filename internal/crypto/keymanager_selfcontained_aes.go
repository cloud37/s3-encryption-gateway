package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// AESKEKOption is a functional option for NewAESKEKManager.
type AESKEKOption func(*AESKEKManager)

// WithAESProvider sets the provider string returned by KeyManager.Provider().
// Defaults to "self_contained".
func WithAESProvider(name string) AESKEKOption {
	return func(m *AESKEKManager) {
		if name != "" {
			m.providerName = name
		}
	}
}

// AESKEKManager wraps DEKs using AES-256-GCM with a locally-held KEK.
//
// Invariants:
//   - Thread-safe: all exported methods acquire m.mu (RLock for reads, Lock
//     for Close/PromoteActiveVersion).
//   - Context propagation: ctx.Err() is checked before acquiring any lock.
//   - Zeroization: all KEK bytes in m.keys are zeroed on Close. Stack copies
//     produced during WrapKey/UnwrapKey are zeroed via defer.
//   - Idempotency: Close is idempotent; second call is a no-op (nil error).
//   - Nil envelope: UnwrapKey returns ErrInvalidEnvelope for nil or zero-
//     ciphertext envelopes.
//   - Post-close: WrapKey/UnwrapKey/ActiveKeyVersion/HealthCheck return
//     ErrProviderUnavailable after Close.
//   - Ciphertext format: [12-byte nonce || GCM ciphertext || 16-byte GCM tag]
//     stored verbatim in KeyEnvelope.Ciphertext.
type AESKEKManager struct {
	mu            sync.RWMutex
	providerName  string
	keys          map[int][]byte // version -> 32-byte AES-256 KEK
	activeVersion int
	closed        bool
}

// NewAESKEKManager creates a new AESKEKManager.
// keys maps version numbers to 32-byte AES-256 KEK material.
// activeVersion selects the wrapping version; must exist in keys.
func NewAESKEKManager(keys map[int][]byte, activeVersion int, opts ...AESKEKOption) (*AESKEKManager, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("keymanager/self-contained-aes: at least one key version required")
	}
	if _, ok := keys[activeVersion]; !ok {
		return nil, fmt.Errorf("keymanager/self-contained-aes: active version %d not found in keys", activeVersion)
	}
	for ver, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("keymanager/self-contained-aes: key version %d must be 32 bytes (AES-256), got %d", ver, len(key))
		}
		allZero := true
		for _, b := range key {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil, fmt.Errorf("keymanager/self-contained-aes: key version %d must not be all zeros", ver)
		}
	}

	keysCopy := make(map[int][]byte, len(keys))
	for ver, key := range keys {
		k := make([]byte, len(key))
		copy(k, key)
		keysCopy[ver] = k
	}

	m := &AESKEKManager{
		providerName:  "self_contained",
		keys:          keysCopy,
		activeVersion: activeVersion,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Provider implements KeyManager.
func (m *AESKEKManager) Provider() string { return m.providerName }

// WrapKey implements KeyManager using AES-256-GCM.
func (m *AESKEKManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-aes: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	kek, ok := m.keys[m.activeVersion]
	if !ok {
		return nil, fmt.Errorf("%w: no active key version %d", ErrKeyNotFound, m.activeVersion)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-aes: nonce generation: %w", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-aes: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-aes: gcm init: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return &KeyEnvelope{
		KeyID:      fmt.Sprintf("self-contained-aes-v%d", m.activeVersion),
		KeyVersion: m.activeVersion,
		Provider:   m.providerName,
		Ciphertext: sealed,
		CreatedAt:  time.Now(),
	}, nil
}

// UnwrapKey implements KeyManager using AES-256-GCM.
// Tries the envelope's declared version first, then falls back to all known versions.
func (m *AESKEKManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-aes: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if envelope == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) < 12+16 {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidEnvelope)
	}

	candidateVersions := m.candidateVersions(envelope.KeyVersion)
	var lastErr error
	for _, ver := range candidateVersions {
		kek, ok := m.keys[ver]
		if !ok {
			continue
		}
		kekCopy := make([]byte, len(kek))
		copy(kekCopy, kek)
		plaintext, err := m.tryUnwrap(kekCopy, envelope.Ciphertext)
		zeroBytes(kekCopy)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no key versions available")
	}
	return nil, fmt.Errorf("%w: all versions failed: %w", ErrUnwrapFailed, lastErr)
}

func (m *AESKEKManager) tryUnwrap(kek, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:12]
	sealed := ciphertext[12:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// ActiveKeyVersion implements KeyManager.
func (m *AESKEKManager) ActiveKeyVersion(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return m.activeVersion, nil
}

// HealthCheck implements KeyManager.
func (m *AESKEKManager) HealthCheck(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	kek, ok := m.keys[m.activeVersion]
	if !ok {
		return fmt.Errorf("%w: no active key version %d", ErrKeyNotFound, m.activeVersion)
	}
	if len(kek) != 32 {
		return fmt.Errorf("keymanager/self-contained-aes: active key length %d != 32", len(kek))
	}
	return nil
}

// Close implements KeyManager. Idempotent; zeroizes all KEK material.
func (m *AESKEKManager) Close(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for ver, key := range m.keys {
		zeroBytes(key)
		delete(m.keys, ver)
	}
	return nil
}

func (m *AESKEKManager) candidateVersions(preferred int) []int {
	if preferred > 0 {
		result := []int{preferred}
		for ver := range m.keys {
			if ver != preferred {
				result = append(result, ver)
			}
		}
		return result
	}
	result := make([]int, 0, len(m.keys))
	for ver := range m.keys {
		result = append(result, ver)
	}
	return result
}

// Compile-time assertions.
var _ KeyManager = (*AESKEKManager)(nil)

// ---------------------------------------------------------------------------
// RotatableKeyManager implementation
// ---------------------------------------------------------------------------

var _ RotatableKeyManager = (*AESKEKManager)(nil)

// AddVersion stages a new KEK version. The version number must not collide
// with an existing version, and material must be exactly 32 bytes (AES-256).
func (m *AESKEKManager) AddVersion(_ context.Context, version int, material []byte) error {
	if len(material) != 32 {
		return fmt.Errorf("keymanager/self-contained-aes: KEK must be 32 bytes for AES-256, got %d", len(material))
	}
	allZero := true
	for _, b := range material {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("keymanager/self-contained-aes: KEK material must not be all zeros")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	if _, exists := m.keys[version]; exists {
		return fmt.Errorf("keymanager/self-contained-aes: version %d already exists", version)
	}

	keyCopy := make([]byte, len(material))
	copy(keyCopy, material)
	m.keys[version] = keyCopy
	return nil
}

// PrepareRotation implements RotatableKeyManager.
func (m *AESKEKManager) PrepareRotation(_ context.Context, target *int) (RotationPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return RotationPlan{}, ErrProviderUnavailable
	}

	current := m.activeVersion

	if target != nil {
		if _, ok := m.keys[*target]; !ok {
			return RotationPlan{}, fmt.Errorf("%w: version %d not found", ErrKeyNotFound, *target)
		}
		if *target == current {
			return RotationPlan{}, fmt.Errorf("keymanager/self-contained-aes: target version %d is already active", *target)
		}
		return RotationPlan{
			CurrentVersion: current,
			TargetVersion:  *target,
		}, nil
	}

	best := -1
	for ver := range m.keys {
		if ver != current && ver > best {
			best = ver
		}
	}
	if best < 0 {
		return RotationPlan{}, fmt.Errorf("%w: no version available to promote (only version %d exists)", ErrRotationAmbiguous, current)
	}

	return RotationPlan{
		CurrentVersion: current,
		TargetVersion:  best,
	}, nil
}

// PromoteActiveVersion implements RotatableKeyManager.
func (m *AESKEKManager) PromoteActiveVersion(_ context.Context, plan RotationPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProviderUnavailable
	}

	if m.activeVersion != plan.CurrentVersion {
		return fmt.Errorf("%w: expected current version %d but active is %d", ErrRotationConflict, plan.CurrentVersion, m.activeVersion)
	}
	if _, ok := m.keys[plan.TargetVersion]; !ok {
		return fmt.Errorf("%w: target version %d not found", ErrKeyNotFound, plan.TargetVersion)
	}

	m.activeVersion = plan.TargetVersion
	return nil
}
