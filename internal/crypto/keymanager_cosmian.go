package crypto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

// KMIPKeyReference describes a wrapping key managed by an external KMIP service.
type KMIPKeyReference struct {
	ID      string
	Version int
}

// CosmianKMIPOptions encapsulates the configuration required to connect to a KMIP-compatible KMS.
type CosmianKMIPOptions struct {
	Endpoint                        string
	Keys                            []KMIPKeyReference
	TLSConfig                       *tls.Config
	Timeout                         time.Duration
	Provider                        string
	DualReadWindow                  int
	InsecureAllowPlaintextTransport bool
}

type cosmianKeyState struct {
	opts          CosmianKMIPOptions
	keyLookup     map[string]KMIPKeyReference
	versionLookup map[int]KMIPKeyReference
	timeout       time.Duration
}

type cosmianKMIPManager struct {
	client *kmipclient.Client
	state  *cosmianKeyState
	mu     sync.RWMutex
}

// NewCosmianKMIPManager creates a KMIP-backed KeyManager implementation.
func NewCosmianKMIPManager(opts CosmianKMIPOptions) (KeyManager, error) {
	state, err := prepareCosmianKeyState(opts)
	if err != nil {
		return nil, err
	}

	if endpointHasScheme(state.opts.Endpoint) {
		return newCosmianKMIPJSONManager(state)
	}

	return newCosmianKMIPBinaryManager(state)
}

func prepareCosmianKeyState(opts CosmianKMIPOptions) (*cosmianKeyState, error) {
	opts.Endpoint = strings.TrimSpace(opts.Endpoint)
	if opts.Endpoint == "" {
		return nil, errors.New("kms: endpoint is required")
	}

	if len(opts.Keys) == 0 {
		return nil, errors.New("kms: at least one wrapping key reference is required")
	}

	keys := make([]KMIPKeyReference, len(opts.Keys))
	for i := range opts.Keys {
		if opts.Keys[i].ID == "" {
			return nil, fmt.Errorf("kms: key reference at index %d missing id", i)
		}
		keys[i] = opts.Keys[i]
		if keys[i].Version == 0 {
			keys[i].Version = i + 1
		}
	}

	provider := opts.Provider
	if provider == "" {
		provider = "cosmian-kmip"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
	}

	keyLookup := make(map[string]KMIPKeyReference, len(keys))
	versionLookup := make(map[int]KMIPKeyReference, len(keys))
	for _, ref := range keys {
		keyLookup[ref.ID] = ref
		versionLookup[ref.Version] = ref
	}

	return &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint:                        opts.Endpoint,
			Keys:                            slices.Clone(keys),
			TLSConfig:                       tlsCfg,
			Timeout:                         timeout,
			Provider:                        provider,
			DualReadWindow:                  opts.DualReadWindow,
			InsecureAllowPlaintextTransport: opts.InsecureAllowPlaintextTransport,
		},
		keyLookup:     keyLookup,
		versionLookup: versionLookup,
		timeout:       timeout,
	}, nil
}

func newCosmianKMIPBinaryManager(state *cosmianKeyState) (KeyManager, error) {
	client, err := kmipclient.Dial(state.opts.Endpoint, kmipclient.WithTlsConfig(state.opts.TLSConfig))
	if err != nil {
		return nil, fmt.Errorf("kms: failed to dial KMIP endpoint %s: %w", state.opts.Endpoint, err)
	}
	return &cosmianKMIPManager{
		client: client,
		state:  state,
	}, nil
}

// Provider implements KeyManager.
func (m *cosmianKMIPManager) Provider() string {
	return m.state.opts.Provider
}

// WrapKey implements KeyManager.
func (m *cosmianKMIPManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("kms: plaintext DEK is empty")
	}
	m.mu.RLock()
	if m.client == nil {
		m.mu.RUnlock()
		return nil, ErrProviderUnavailable
	}
	m.mu.RUnlock()
	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()
	active := m.state.opts.Keys[0]

	resp, err := m.client.
		Encrypt(active.ID).
		WithCryptographicParameters(m.defaultCryptoParams()).
		Data(plaintext).
		ExecContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: encrypt failed (key ID: %s): %w", active.ID, err)
	}

	keyID := resp.UniqueIdentifier
	if keyID == "" {
		keyID = active.ID
	}
	version := active.Version
	if ref, ok := m.state.keyLookup[keyID]; ok {
		version = ref.Version
	}

	return &KeyEnvelope{
		KeyID:      keyID,
		KeyVersion: version,
		Provider:   m.Provider(),
		Ciphertext: resp.Data,
	}, nil
}

// UnwrapKey implements KeyManager.
func (m *cosmianKMIPManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if envelope == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: wrapped key is empty", ErrInvalidEnvelope)
	}
	m.mu.RLock()
	if m.client == nil {
		m.mu.RUnlock()
		return nil, ErrProviderUnavailable
	}
	m.mu.RUnlock()
	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	candidates := m.state.candidateKeys(envelope)
	if len(candidates) == 0 {
		return nil, errors.New("kms: no key candidates available for unwrap")
	}

	var lastErr error
	attempts := 0
	maxAttempts := m.state.opts.DualReadWindow + 1
	if maxAttempts <= 0 {
		maxAttempts = len(candidates) // Try all if DualReadWindow is 0 or negative
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if attempts >= maxAttempts {
			break
		}
		resp, err := m.client.
			Decrypt(candidate).
			WithCryptographicParameters(m.defaultCryptoParams()).
			Data(envelope.Ciphertext).
			ExecContext(ctx)
		if err == nil {
			return resp.Data, nil
		}
		lastErr = err
		attempts++
	}

	if lastErr == nil {
		lastErr = errors.New("kms: unwrap failed with no attempts recorded")
	}
	return nil, fmt.Errorf("kms: decrypt failed: %w", fmt.Errorf("%w: %w", ErrUnwrapFailed, lastErr))
}

// ActiveKeyVersion implements KeyManager.
func (m *cosmianKMIPManager) ActiveKeyVersion(_ context.Context) (int, error) {
	if len(m.state.opts.Keys) == 0 {
		return 0, errors.New("kms: no keys configured")
	}
	return m.state.opts.Keys[0].Version, nil
}

// HealthCheck implements KeyManager.
func (m *cosmianKMIPManager) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	closed := m.client == nil
	m.mu.RUnlock()
	if closed {
		return fmt.Errorf("kms: client not initialized: %w", ErrProviderUnavailable)
	}
	if len(m.state.opts.Keys) == 0 {
		return errors.New("kms: no keys configured")
	}

	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	// Perform a lightweight Get operation on the first key to verify connectivity
	// This doesn't perform encryption/decryption, just verifies the KMS is reachable
	active := m.state.opts.Keys[0]
	_, err := m.client.Get(active.ID).ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("kms: health check failed (key ID: %s): %w", active.ID, err)
	}
	return nil
}

// Close implements KeyManager.
func (m *cosmianKMIPManager) Close(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		err := m.client.Close()
		m.client = nil
		return err
	}
	return nil
}

func (m *cosmianKMIPManager) defaultCryptoParams() kmip.CryptographicParameters {
	// BlockCipherMode is intentionally omitted: Cosmian KMS selects AES-KW (RFC 3394)
	// or AES-GCM internally — both are suitable for key wrapping.
	// ECB is NOT used by this gateway and is unsuitable for key wrapping
	// (deterministic, no diffusion across blocks).
	return kmip.CryptographicParameters{
		CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
		PaddingMethod:          kmip.PaddingMethodNone,
	}
}

func (s *cosmianKeyState) candidateKeys(env *KeyEnvelope) []string {
	result := make([]string, 0, len(s.opts.Keys))
	seen := make(map[string]struct{})

	id := env.KeyID
	if id == "" && env.KeyVersion != 0 {
		if ref, ok := s.versionLookup[env.KeyVersion]; ok {
			id = ref.ID
		}
	}
	if id != "" {
		result = append(result, id)
		seen[id] = struct{}{}
	}

	for _, ref := range s.opts.Keys {
		if _, ok := seen[ref.ID]; ok {
			continue
		}
		result = append(result, ref.ID)
		seen[ref.ID] = struct{}{}
	}
	return result
}

func (s *cosmianKeyState) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.timeout)
}

func endpointHasScheme(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		return err == nil && u.Scheme != ""
	}
	return false
}

// ---------------------------------------------------------------------------
// RotatableKeyManager implementation for Cosmian KMIP adapter
// ---------------------------------------------------------------------------

// Compile-time assertion that *cosmianKMIPManager implements RotatableKeyManager.
var _ RotatableKeyManager = (*cosmianKMIPManager)(nil)

// PrepareRotation implements [RotatableKeyManager]. For the Cosmian adapter,
// rotation means promoting a different configured KMIPKeyReference to index 0.
// If target is nil, it picks the next-higher version number not currently active.
func (m *cosmianKMIPManager) PrepareRotation(_ context.Context, target *int) (RotationPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil {
		return RotationPlan{}, ErrProviderUnavailable
	}

	keys := m.state.opts.Keys
	if len(keys) < 2 {
		return RotationPlan{}, fmt.Errorf("%w: at least two key references are required for rotation", ErrRotationAmbiguous)
	}

	currentVersion := keys[0].Version

	if target != nil {
		// Find the referenced version
		for _, ref := range keys {
			if ref.Version == *target {
				if ref.Version == currentVersion {
					return RotationPlan{}, fmt.Errorf("keymanager/cosmian: target version %d is already active", *target)
				}
				return RotationPlan{
					CurrentVersion: currentVersion,
					TargetVersion:  ref.Version,
					ProviderData:   map[string]string{"key_id": ref.ID},
				}, nil
			}
		}
		return RotationPlan{}, fmt.Errorf("%w: version %d not found in configured keys", ErrKeyNotFound, *target)
	}

	// Auto-select: pick the highest version that isn't active
	best := -1
	var bestID string
	for _, ref := range keys {
		if ref.Version != currentVersion && ref.Version > best {
			best = ref.Version
			bestID = ref.ID
		}
	}
	if best < 0 {
		return RotationPlan{}, fmt.Errorf("%w: no version available to promote", ErrRotationAmbiguous)
	}

	return RotationPlan{
		CurrentVersion: currentVersion,
		TargetVersion:  best,
		ProviderData:   map[string]string{"key_id": bestID},
	}, nil
}

// PromoteActiveVersion implements [RotatableKeyManager]. Reorders opts.Keys
// so the target version becomes index 0 (the active key).
func (m *cosmianKMIPManager) PromoteActiveVersion(_ context.Context, plan RotationPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return ErrProviderUnavailable
	}

	keys := m.state.opts.Keys
	if len(keys) == 0 {
		return fmt.Errorf("keymanager/cosmian: no keys configured")
	}

	// Validate current version matches
	if keys[0].Version != plan.CurrentVersion {
		return fmt.Errorf("%w: expected current version %d but active is %d", ErrRotationConflict, plan.CurrentVersion, keys[0].Version)
	}

	// Find and promote target
	targetIdx := -1
	for i, ref := range keys {
		if ref.Version == plan.TargetVersion {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		return fmt.Errorf("%w: target version %d not found", ErrKeyNotFound, plan.TargetVersion)
	}

	// Move target to index 0
	targetRef := keys[targetIdx]
	newKeys := make([]KMIPKeyReference, 0, len(keys))
	newKeys = append(newKeys, targetRef)
	for i, ref := range keys {
		if i != targetIdx {
			newKeys = append(newKeys, ref)
		}
	}
	m.state.opts.Keys = newKeys

	// Rebuild lookups
	m.state.keyLookup = make(map[string]KMIPKeyReference, len(newKeys))
	m.state.versionLookup = make(map[int]KMIPKeyReference, len(newKeys))
	for _, ref := range newKeys {
		m.state.keyLookup[ref.ID] = ref
		m.state.versionLookup[ref.Version] = ref
	}

	return nil
}
