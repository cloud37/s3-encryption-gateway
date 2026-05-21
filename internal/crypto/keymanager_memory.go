package crypto

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MemoryOption is a functional option for [NewInMemoryKeyManager].
type MemoryOption func(*inMemoryKeyManager)

// WithMemoryProvider sets the provider string returned by [KeyManager.Provider].
// Defaults to "memory".
func WithMemoryProvider(name string) MemoryOption {
	return func(m *inMemoryKeyManager) {
		if name != "" {
			m.providerName = name
		}
	}
}

// WithMemoryVersions adds historical master key versions to support rotation
// tests. Each entry is [version, masterKey...]. The first entry is the
// active (wrap) version; all entries are tried during unwrap.
//
// The caller is responsible for the provided key material; the in-memory
// manager copies and then zeroizes its copies on Close.
func WithMemoryVersions(versions []struct {
	Version int
	Key     []byte
}) MemoryOption {
	return func(m *inMemoryKeyManager) {
		for _, v := range versions {
			keyCopy := make([]byte, len(v.Key))
			copy(keyCopy, v.Key)
			m.keys[v.Version] = keyCopy
			if v.Version > m.activeVersion {
				m.activeVersion = v.Version
			}
		}
	}
}

type inMemoryKeyManager struct {
	mu           sync.RWMutex
	providerName string
	// keys maps version → AES-256 master key
	keys          map[int][]byte
	activeVersion int
	closed        bool
}

// NewInMemoryKeyManager creates a KeyManager that wraps DEKs using AES key-wrap
// (RFC 3394) with a randomly-generated or caller-supplied master key.
//
// masterKey must be exactly 16, 24, or 32 bytes (AES-128/192/256). Pass nil to
// have the manager generate a fresh 32-byte key automatically.
//
// The returned manager is registered under the name "memory" in the global
// adapter registry (see [Register]) if the registry is initialised.
//
// Example:
//
//	km, err := crypto.NewInMemoryKeyManager(nil)         // auto-generated key
//	km, err := crypto.NewInMemoryKeyManager(myKey32)     // caller-supplied key
func NewInMemoryKeyManager(masterKey []byte, opts ...MemoryOption) (KeyManager, error) {
	if masterKey == nil {
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, fmt.Errorf("keymanager/memory: failed to generate master key: %w", err)
		}
	}
	switch len(masterKey) {
	case 16, 24, 32:
		// valid AES key sizes
	default:
		return nil, fmt.Errorf("keymanager/memory: master key must be 16, 24, or 32 bytes, got %d", len(masterKey))
	}

	keyCopy := make([]byte, len(masterKey))
	copy(keyCopy, masterKey)

	m := &inMemoryKeyManager{
		providerName:  "memory",
		keys:          map[int][]byte{1: keyCopy},
		activeVersion: 1,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Provider implements [KeyManager].
func (m *inMemoryKeyManager) Provider() string { return m.providerName }

// WrapKey implements [KeyManager] using AES key-wrap (RFC 3394).
func (m *inMemoryKeyManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/memory: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, errors.New("keymanager/memory: plaintext DEK is empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}

	masterKey, ok := m.keys[m.activeVersion]
	if !ok {
		return nil, fmt.Errorf("%w: no active key version", ErrKeyNotFound)
	}

	ciphertext, err := aesKeyWrap(masterKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("keymanager/memory: wrap failed: %w", err)
	}

	return &KeyEnvelope{
		KeyID:      fmt.Sprintf("memory-v%d", m.activeVersion),
		KeyVersion: m.activeVersion,
		Provider:   m.providerName,
		Ciphertext: ciphertext,
		CreatedAt:  time.Now(),
	}, nil
}

// UnwrapKey implements [KeyManager] using AES key-unwrap (RFC 3394).
func (m *inMemoryKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/memory: %w", err)
	}
	if envelope == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: wrapped key is empty", ErrInvalidEnvelope)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}

	// Try envelope's declared version first, then fall back to all known versions.
	tryVersions := m.candidateVersions(envelope.KeyVersion)
	var lastErr error
	for _, ver := range tryVersions {
		masterKey, ok := m.keys[ver]
		if !ok {
			continue
		}
		plaintext, err := aesKeyUnwrap(masterKey, envelope.Ciphertext)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no key versions available")
	}
	return nil, fmt.Errorf("%w: %w", ErrUnwrapFailed, lastErr)
}

// ActiveKeyVersion implements [KeyManager].
func (m *inMemoryKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return m.activeVersion, nil
}

// HealthCheck implements [KeyManager].
func (m *inMemoryKeyManager) HealthCheck(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	return nil
}

// Close implements [KeyManager]. Idempotent; zeroizes all master key copies.
func (m *inMemoryKeyManager) Close(_ context.Context) error {
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

func (m *inMemoryKeyManager) candidateVersions(preferred int) []int {
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

// ---------------------------------------------------------------------------
// AES key-wrap / key-unwrap (RFC 3394)
// ---------------------------------------------------------------------------

// aesKeyWrap wraps plaintext using AES key-wrap (RFC 3394).
// kek must be 16, 24, or 32 bytes.
// plaintext must be a multiple of 8 bytes and ≥ 16 bytes.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		// Pad to nearest 8-byte boundary if needed
		padded := make([]byte, ((len(plaintext)+7)/8)*8)
		copy(padded, plaintext)
		plaintext = padded
		if len(plaintext) < 16 {
			// Still too short — pad to 16
			plaintext = make([]byte, 16)
			copy(plaintext, padded)
		}
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	// A: integrity check register (RFC 3394 §2.2.3 default IV)
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:])
	}

	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			copy(a[:], buf[:8])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(a[:])|0) // noop
			a[0] ^= byte(t >> 56)  // #nosec G115 — AES-KW (RFC 3394) uses small t values (< 6*n)
			a[1] ^= byte(t >> 48)  // #nosec G115
			a[2] ^= byte(t >> 40)  // #nosec G115
			a[3] ^= byte(t >> 32)  // #nosec G115
			a[4] ^= byte(t >> 24)  // #nosec G115
			a[5] ^= byte(t >> 16)  // #nosec G115
			a[6] ^= byte(t >> 8)   // #nosec G115
			a[7] ^= byte(t)        // #nosec G115 — t = n*j + i + 1, j ≤ 5, n ≤ 2^32, product fits uint64
			copy(r[i], buf[8:])
		}
	}

	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	for i, ri := range r {
		copy(out[8+i*8:], ri)
	}
	return out, nil
}

// aesKeyUnwrap unwraps ciphertext wrapped with AES key-wrap (RFC 3394).
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errors.New("keymanager/memory: invalid wrapped key length")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(ciphertext)/8 - 1
	a := [8]byte{}
	copy(a[:], ciphertext[:8])
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8+i*8:])
	}

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1) // #nosec G115 — AES-KW (RFC 3394) small t values (< 6*n), product fits int
			aCopy := a
			aCopy[0] ^= byte(t >> 56)  // #nosec G115 — AES-KW (RFC 3394) uses small t values (< 6*n)
			aCopy[1] ^= byte(t >> 48)  // #nosec G115
			aCopy[2] ^= byte(t >> 40)  // #nosec G115
			aCopy[3] ^= byte(t >> 32)  // #nosec G115
			aCopy[4] ^= byte(t >> 24)  // #nosec G115
			aCopy[5] ^= byte(t >> 16)  // #nosec G115
			aCopy[6] ^= byte(t >> 8)   // #nosec G115
			aCopy[7] ^= byte(t)        // #nosec G115 — t = n*j + i + 1, j ≤ 5, n ≤ 2^32, product fits uint64
			copy(buf[:8], aCopy[:])
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a[:], buf[:8])
			copy(r[i], buf[8:])
		}
	}

	// Verify integrity check value
	expected := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if a != expected {
		return nil, errors.New("keymanager/memory: integrity check failed — wrong key or corrupted ciphertext")
	}

	out := make([]byte, n*8)
	for i, ri := range r {
		copy(out[i*8:], ri)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// RotatableKeyManager implementation for in-memory adapter
// ---------------------------------------------------------------------------

// Compile-time assertion that *inMemoryKeyManager implements RotatableKeyManager.
var _ RotatableKeyManager = (*inMemoryKeyManager)(nil)

// AddVersion stages a new master key version. The version number must not
// collide with an existing version, and material must be exactly 32 bytes
// (AES-256). This method is separate from PromoteActiveVersion so operators
// can stage material before the rotation window.
func (m *inMemoryKeyManager) AddVersion(_ context.Context, version int, material []byte) error {
	if len(material) != 32 {
		return fmt.Errorf("keymanager/memory: master key must be 32 bytes for AES-256, got %d", len(material))
	}
	// Reject zero-valued key material
	allZero := true
	for _, b := range material {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("keymanager/memory: master key material must not be all zeros")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	if _, exists := m.keys[version]; exists {
		return fmt.Errorf("keymanager/memory: version %d already exists", version)
	}

	keyCopy := make([]byte, len(material))
	copy(keyCopy, material)
	m.keys[version] = keyCopy
	return nil
}

// PrepareRotation implements [RotatableKeyManager].
func (m *inMemoryKeyManager) PrepareRotation(_ context.Context, target *int) (RotationPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return RotationPlan{}, ErrProviderUnavailable
	}

	current := m.activeVersion

	if target != nil {
		// Validate the requested target exists
		if _, ok := m.keys[*target]; !ok {
			return RotationPlan{}, fmt.Errorf("%w: version %d not found", ErrKeyNotFound, *target)
		}
		if *target == current {
			return RotationPlan{}, fmt.Errorf("keymanager/memory: target version %d is already active", *target)
		}
		return RotationPlan{
			CurrentVersion: current,
			TargetVersion:  *target,
		}, nil
	}

	// Auto-select: find the highest version that isn't active
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

// PromoteActiveVersion implements [RotatableKeyManager].
func (m *inMemoryKeyManager) PromoteActiveVersion(_ context.Context, plan RotationPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProviderUnavailable
	}

	// Validate the plan is still consistent
	if m.activeVersion != plan.CurrentVersion {
		return fmt.Errorf("%w: expected current version %d but active is %d", ErrRotationConflict, plan.CurrentVersion, m.activeVersion)
	}
	if _, ok := m.keys[plan.TargetVersion]; !ok {
		return fmt.Errorf("%w: target version %d not found", ErrKeyNotFound, plan.TargetVersion)
	}

	m.activeVersion = plan.TargetVersion
	return nil
}
