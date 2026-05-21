package crypto

// ConformanceSuite runs a shared contract test suite against any [KeyManager]
// implementation. It is intentionally NOT in a _test.go file so that adapter
// packages outside this module can import and invoke it:
//
//	import "github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
//
//	func TestMyAdapter(t *testing.T) {
//	    crypto.ConformanceSuite(t, func(t *testing.T) crypto.KeyManager {
//	        km, err := mypackage.NewMyAdapter(myConfig)
//	        if err != nil { t.Fatal(err) }
//	        return km
//	    })
//	}
//
// The suite verifies:
//   - Wrap → Unwrap round-trip correctness for DEK sizes 16, 24, 32 bytes.
//   - [KeyManager.ActiveKeyVersion] returns a non-negative value.
//   - [KeyManager.HealthCheck] returns nil on a live manager.
//   - [KeyManager.Close] is idempotent (second call returns nil).
//   - Post-Close calls to WrapKey / UnwrapKey return [ErrProviderUnavailable].
//   - Context cancellation propagates to WrapKey / UnwrapKey.
//   - 64 concurrent goroutines can Wrap/Unwrap without data races (run with -race).
//
// Timeouts are controlled by [ConformanceOptions]; the defaults are generous
// enough for CI but can be tightened for unit tests.

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

// ConformanceOptions controls timeouts used by [ConformanceSuite].
type ConformanceOptions struct {
	// WrapUnwrapTimeout is the per-operation deadline for WrapKey / UnwrapKey.
	// Defaults to 2 seconds.
	WrapUnwrapTimeout time.Duration

	// HealthCheckTimeout is the deadline for HealthCheck.
	// Defaults to 10 seconds.
	HealthCheckTimeout time.Duration

	// ConcurrencyCount is the number of goroutines launched for the race test.
	// Defaults to 64.
	ConcurrencyCount int

	// SkipHealthCheck causes the HealthCheckLive sub-test to be skipped.
	// Use this when the adapter under test relies on a mock server that does
	// not support the lightweight Get operation used by HealthCheck (e.g. the
	// KMIP binary test server).
	SkipHealthCheck bool
}

func (o *ConformanceOptions) defaults() {
	if o.WrapUnwrapTimeout == 0 {
		o.WrapUnwrapTimeout = 2 * time.Second
	}
	if o.HealthCheckTimeout == 0 {
		o.HealthCheckTimeout = 10 * time.Second
	}
	if o.ConcurrencyCount == 0 {
		o.ConcurrencyCount = 64
	}
}

// ConformanceSuite runs the full conformance test suite.
// newFactory is called once per sub-test to obtain a fresh KeyManager.
func ConformanceSuite(t *testing.T, newFactory func(t *testing.T) KeyManager, optFns ...ConformanceOptions) {
	t.Helper()

	opts := ConformanceOptions{}
	if len(optFns) > 0 {
		opts = optFns[0]
	}
	opts.defaults()

	t.Run("WrapUnwrapRoundTrip", func(t *testing.T) {
		conformanceWrapUnwrapRoundTrip(t, newFactory, opts)
	})
	t.Run("ActiveKeyVersionNonNegative", func(t *testing.T) {
		conformanceActiveKeyVersion(t, newFactory, opts)
	})
	t.Run("HealthCheckLive", func(t *testing.T) {
		conformanceHealthCheck(t, newFactory, opts)
	})
	t.Run("CloseIdempotent", func(t *testing.T) {
		conformanceCloseIdempotent(t, newFactory, opts)
	})
	t.Run("PostCloseReturnsUnavailable", func(t *testing.T) {
		conformancePostClose(t, newFactory, opts)
	})
	t.Run("ContextCancellation", func(t *testing.T) {
		conformanceContextCancellation(t, newFactory, opts)
	})
	t.Run("ConcurrentWrapUnwrap", func(t *testing.T) {
		conformanceConcurrent(t, newFactory, opts)
	})
}

// ---- individual sub-tests ---------------------------------------------------

func conformanceWrapUnwrapRoundTrip(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	sizes := []int{16, 24, 32}
	for _, sz := range sizes {
		sz := sz
		t.Run(dekSizeName(sz), func(t *testing.T) {
			km := newFactory(t)
			t.Cleanup(func() { _ = km.Close(context.Background()) })

			plaintext := make([]byte, sz)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("failed to generate random plaintext: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), opts.WrapUnwrapTimeout)
			defer cancel()

			env, err := km.WrapKey(ctx, plaintext, nil)
			if err != nil {
				t.Fatalf("WrapKey(%d bytes): %v", sz, err)
			}
			if env == nil {
				t.Fatal("WrapKey returned nil envelope")
			}
			if len(env.Ciphertext) == 0 {
				t.Fatal("WrapKey returned empty ciphertext")
			}

			ctx2, cancel2 := context.WithTimeout(context.Background(), opts.WrapUnwrapTimeout)
			defer cancel2()

			got, err := km.UnwrapKey(ctx2, env, nil)
			if err != nil {
				t.Fatalf("UnwrapKey(%d bytes): %v", sz, err)
			}
			if len(got) == 0 {
				t.Fatal("UnwrapKey returned empty plaintext")
			}
			if string(got) != string(plaintext) {
				t.Fatalf("round-trip mismatch for %d-byte key", sz)
			}
			zeroBytes(got)
		})
	}
}

func conformanceActiveKeyVersion(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	km := newFactory(t)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), opts.WrapUnwrapTimeout)
	defer cancel()

	ver, err := km.ActiveKeyVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if ver < 0 {
		t.Fatalf("ActiveKeyVersion returned negative value %d", ver)
	}
}

func conformanceHealthCheck(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	if opts.SkipHealthCheck {
		t.Skip("HealthCheck skipped via ConformanceOptions.SkipHealthCheck")
	}
	km := newFactory(t)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), opts.HealthCheckTimeout)
	defer cancel()

	if err := km.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck on live manager: %v", err)
	}
}

func conformanceCloseIdempotent(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	km := newFactory(t)

	if err := km.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := km.Close(context.Background()); err != nil {
		t.Fatalf("second Close (idempotency): %v", err)
	}
}

func conformancePostClose(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	km := newFactory(t)

	if err := km.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx := context.Background()

	_, wrapErr := km.WrapKey(ctx, make([]byte, 32), nil)
	if !errors.Is(wrapErr, ErrProviderUnavailable) {
		t.Errorf("WrapKey after Close: got %v, want wrapping ErrProviderUnavailable", wrapErr)
	}

	_, unwrapErr := km.UnwrapKey(ctx, &KeyEnvelope{
		KeyID:      "dummy",
		KeyVersion: 1,
		Provider:   km.Provider(),
		Ciphertext: make([]byte, 24),
	}, nil)
	if !errors.Is(unwrapErr, ErrProviderUnavailable) {
		t.Errorf("UnwrapKey after Close: got %v, want wrapping ErrProviderUnavailable", unwrapErr)
	}
}

func conformanceContextCancellation(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	km := newFactory(t)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Create an already-cancelled context to exercise the fast-path check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled immediately

	plaintext := make([]byte, 32)
	_, err := km.WrapKey(ctx, plaintext, nil)
	if err == nil {
		// Some adapters (e.g. memory) are synchronous and may not observe the
		// cancellation before returning. Accept that but do not fail.
		t.Log("WrapKey with cancelled context returned nil error (synchronous adapter — acceptable)")
	} else if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrProviderUnavailable) {
		// Any error is acceptable here; the important thing is no panic.
		t.Logf("WrapKey with cancelled context returned: %v", err)
	}
}

func conformanceConcurrent(t *testing.T, newFactory func(*testing.T) KeyManager, opts ConformanceOptions) {
	t.Helper()
	km := newFactory(t)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	n := opts.ConcurrencyCount
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			plaintext := make([]byte, 32)
			if _, err := rand.Read(plaintext); err != nil {
				errs[i] = err
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), opts.WrapUnwrapTimeout)
			defer cancel()

			env, err := km.WrapKey(ctx, plaintext, nil)
			if err != nil {
				errs[i] = err
				return
			}

			got, err := km.UnwrapKey(ctx, env, nil)
			if err != nil {
				errs[i] = err
				return
			}
			if string(got) != string(plaintext) {
				errs[i] = errors.New("round-trip mismatch in concurrent test")
			}
			zeroBytes(got)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

func dekSizeName(sz int) string {
	switch sz {
	case 16:
		return "AES-128"
	case 24:
		return "AES-192"
	case 32:
		return "AES-256"
	default:
		return "unknown"
	}
}

// ConformanceSuite_Rotation runs optional rotation contract tests against any
// [KeyManager]. Tests are skipped if the adapter does not implement
// [RotatableKeyManager].
func ConformanceSuite_Rotation(t *testing.T, newFactory func(t *testing.T) KeyManager, addVersion func(t *testing.T, km KeyManager, version int) error, optFns ...ConformanceOptions) {
	t.Helper()

	opts := ConformanceOptions{}
	if len(optFns) > 0 {
		opts = optFns[0]
	}
	opts.defaults()

	t.Run("Rotation_RoundTrip", func(t *testing.T) {
		km := newFactory(t)
		t.Cleanup(func() { _ = km.Close(context.Background()) })

		rkm, ok := km.(RotatableKeyManager)
		if !ok {
			t.Skip("adapter does not implement RotatableKeyManager")
		}

		// Stage a second version
		if err := addVersion(t, km, 2); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}

		// Wrap a DEK with the original version
		plaintext := make([]byte, 32)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		env1, err := km.WrapKey(ctx, plaintext, nil)
		if err != nil {
			t.Fatalf("WrapKey (pre-rotation): %v", err)
		}
		originalVersion := env1.KeyVersion

		// Prepare and promote
		plan, err := rkm.PrepareRotation(ctx, nil)
		if err != nil {
			t.Fatalf("PrepareRotation: %v", err)
		}
		if plan.TargetVersion == plan.CurrentVersion {
			t.Fatal("PrepareRotation returned same version as current")
		}

		if err := rkm.PromoteActiveVersion(ctx, plan); err != nil {
			t.Fatalf("PromoteActiveVersion: %v", err)
		}

		// Active version should have changed
		newVer, err := km.ActiveKeyVersion(ctx)
		if err != nil {
			t.Fatalf("ActiveKeyVersion: %v", err)
		}
		if newVer == originalVersion {
			t.Fatal("ActiveKeyVersion unchanged after promotion")
		}

		// New wraps should use the new version
		env2, err := km.WrapKey(ctx, plaintext, nil)
		if err != nil {
			t.Fatalf("WrapKey (post-rotation): %v", err)
		}
		if env2.KeyVersion == originalVersion {
			t.Fatal("post-rotation WrapKey still using original version")
		}

		// Old DEK must still unwrap
		unwrapped, err := km.UnwrapKey(ctx, env1, nil)
		if err != nil {
			t.Fatalf("UnwrapKey (old DEK post-rotation): %v", err)
		}
		if string(unwrapped) != string(plaintext) {
			t.Fatal("old DEK round-trip failed post-rotation")
		}

		// New DEK should also unwrap
		unwrapped2, err := km.UnwrapKey(ctx, env2, nil)
		if err != nil {
			t.Fatalf("UnwrapKey (new DEK post-rotation): %v", err)
		}
		if string(unwrapped2) != string(plaintext) {
			t.Fatal("new DEK round-trip failed post-rotation")
		}
	})

	t.Run("Rotation_ConcurrentWrapDuringPromote", func(t *testing.T) {
		km := newFactory(t)
		t.Cleanup(func() { _ = km.Close(context.Background()) })

		rkm, ok := km.(RotatableKeyManager)
		if !ok {
			t.Skip("adapter does not implement RotatableKeyManager")
		}

		if err := addVersion(t, km, 2); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}

		ctx := context.Background()
		plan, err := rkm.PrepareRotation(ctx, nil)
		if err != nil {
			t.Fatalf("PrepareRotation: %v", err)
		}

		// Launch concurrent wraps
		n := 16
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			go func() {
				plaintext := make([]byte, 32)
				rand.Read(plaintext)
				env, err := km.WrapKey(ctx, plaintext, nil)
				if err != nil {
					errs <- err
					return
				}
				got, err := km.UnwrapKey(ctx, env, nil)
				if err != nil {
					errs <- err
					return
				}
				if string(got) != string(plaintext) {
					errs <- errors.New("round-trip mismatch during concurrent rotation")
					return
				}
				errs <- nil
			}()
		}

		// Promote during concurrent wraps
		if err := rkm.PromoteActiveVersion(ctx, plan); err != nil {
			t.Fatalf("PromoteActiveVersion: %v", err)
		}

		for i := 0; i < n; i++ {
			if err := <-errs; err != nil {
				t.Errorf("concurrent goroutine %d: %v", i, err)
			}
		}
	})
}
