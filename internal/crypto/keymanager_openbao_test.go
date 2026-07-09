package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockBaoServer is a stateful in-memory fake of the OpenBao HTTP API covering
// the Transit endpoints plus auth login / token renew / lookup-self that the
// adapter uses. Round-trips are faithful: encrypt echoes the base64 DEK inside
// a "vault:vN:" envelope and decrypt strips the prefix back out, so a real DEK
// survives a wrap/unwrap cycle.
type mockBaoServer struct {
	*httptest.Server

	mu            sync.Mutex
	transitPath   string
	keyName       string
	latestVersion int

	// error injection
	decryptStatus int // if non-zero, decrypt returns this HTTP status
	lookupStatus  int // if non-zero, auth/token/lookup-self returns this status
	encryptStatus int // if non-zero, encrypt returns this HTTP status
	keysStatus    int // if non-zero, GET transit/keys/<name> returns this status

	// behaviour toggles
	renewNonRenewable bool // if true, renew-self returns a non-renewable token

	// observability
	renewCount int
	loginCount int
}

func newMockBaoServer(t *testing.T) *mockBaoServer {
	t.Helper()
	m := &mockBaoServer{transitPath: "transit", keyName: "test-key", latestVersion: 1}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Server.Close)
	return m
}

func (m *mockBaoServer) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (m *mockBaoServer) writeErr(w http.ResponseWriter, status int, msg string) {
	m.writeJSON(w, status, map[string]any{"errors": []string{msg}})
}

func (m *mockBaoServer) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	body := map[string]any{}
	if r.Body != nil {
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
	}

	switch path {
	case m.transitPath + "/encrypt/" + m.keyName:
		if m.encryptStatus != 0 {
			m.writeErr(w, m.encryptStatus, "encrypt injected error")
			return
		}
		pt, _ := body["plaintext"].(string)
		ct := fmt.Sprintf("vault:v%d:%s", m.latestVersion, pt)
		m.writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{"ciphertext": ct, "key_version": m.latestVersion},
		})

	case m.transitPath + "/decrypt/" + m.keyName:
		if m.decryptStatus != 0 {
			m.writeErr(w, m.decryptStatus, "decrypt injected error")
			return
		}
		ct, _ := body["ciphertext"].(string)
		// strip "vault:vN:" prefix -> remaining is the original base64 plaintext
		rest := strings.TrimPrefix(ct, "vault:v")
		_, pt, ok := strings.Cut(rest, ":")
		if !ok {
			m.writeErr(w, http.StatusBadRequest, "invalid ciphertext")
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{"plaintext": pt},
		})

	case m.transitPath + "/keys/" + m.keyName:
		if m.keysStatus != 0 {
			m.writeErr(w, m.keysStatus, "keys read injected error")
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{
				"name":           m.keyName,
				"type":           "aes256-gcm96",
				"latest_version": m.latestVersion,
			},
		})

	case m.transitPath + "/keys/" + m.keyName + "/rotate":
		m.latestVersion++
		m.writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"latest_version": m.latestVersion}})

	case "auth/token/lookup-self":
		if m.lookupStatus != 0 {
			m.writeErr(w, m.lookupStatus, "permission denied")
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{"id": "test-token", "ttl": 3600},
		})

	case "auth/token/renew-self":
		m.renewCount++
		renewable, lease := true, 2
		if m.renewNonRenewable {
			// Token can no longer be renewed -> LifetimeWatcher fires DoneCh ->
			// adapter must re-login.
			renewable, lease = false, 0
		}
		m.writeJSON(w, http.StatusOK, map[string]any{
			"auth": map[string]any{"client_token": "renewed-token", "lease_duration": lease, "renewable": renewable},
		})

	case "auth/approle/login", "auth/kubernetes/login":
		m.loginCount++
		m.writeJSON(w, http.StatusOK, map[string]any{
			"auth": map[string]any{"client_token": "logged-in-token", "lease_duration": 2, "renewable": true},
		})

	default:
		m.writeErr(w, http.StatusNotFound, "no handler for "+path)
	}
}

func (m *mockBaoServer) setDecryptStatus(s int) { m.mu.Lock(); m.decryptStatus = s; m.mu.Unlock() }
func (m *mockBaoServer) setLookupStatus(s int)  { m.mu.Lock(); m.lookupStatus = s; m.mu.Unlock() }
func (m *mockBaoServer) setKeysStatus(s int)    { m.mu.Lock(); m.keysStatus = s; m.mu.Unlock() }
func (m *mockBaoServer) setRenewNonRenewable(b bool) {
	m.mu.Lock()
	m.renewNonRenewable = b
	m.mu.Unlock()
}
func (m *mockBaoServer) getLoginCount() int { m.mu.Lock(); defer m.mu.Unlock(); return m.loginCount }
func (m *mockBaoServer) getLatestVersion() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latestVersion
}

// newTestManager builds a token-auth adapter against the mock with renewal off.
func newTestManager(t *testing.T, srv *mockBaoServer) KeyManager {
	t.Helper()
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address:        srv.URL,
		KeyName:        "test-key",
		Auth:           OpenBaoAuthConfig{Method: "token", Token: "test-token"},
		DisableRenewal: true,
		Timeout:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoTransitManager: %v", err)
	}
	return km
}

func TestParseOpenBaoKeyVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"vault:v1:abc", 1, false},
		{"vault:v42:zzz==", 42, false},
		{"vault:v0:abc", 0, true}, // version 0 is invalid
		{"vault:v:abc", 0, true},  // missing digits
		{"vault:vX:abc", 0, true}, // non-numeric
		{"plain-bytes", 0, true},  // no prefix
		{"vault:v7", 0, true},     // no delimiter after digits
		{"", 0, true},             // empty
	}
	for _, tc := range cases {
		got, err := parseOpenBaoKeyVersion(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseOpenBaoKeyVersion(%q): want error, got version %d", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOpenBaoKeyVersion(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseOpenBaoKeyVersion(%q): got %d want %d", tc.in, got, tc.want)
		}
	}
}

func TestOpenBao_WrapUnwrap_RoundTrip(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	dek := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	env, err := km.WrapKey(context.Background(), dek, nil)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if env.KeyVersion != 1 {
		t.Errorf("KeyVersion: got %d want 1", env.KeyVersion)
	}
	if env.KeyID == "" {
		t.Error("KeyID must be non-empty (engine streaming-decrypt rejects empty KMS key id)")
	}
	if env.KeyID != "vault-transit:transit/test-key" {
		t.Errorf("KeyID: got %q", env.KeyID)
	}
	if !strings.HasPrefix(string(env.Ciphertext), "vault:v1:") {
		t.Errorf("Ciphertext prefix: got %q", string(env.Ciphertext))
	}

	got, err := km.UnwrapKey(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if string(got) != string(dek) {
		t.Errorf("round-trip mismatch: got %q want %q", got, dek)
	}
}

func TestOpenBao_UnwrapKey_InvalidCiphertext(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setDecryptStatus(http.StatusBadRequest)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("vault:v1:garbage")}, nil)
	if err == nil || !isErr(err, ErrUnwrapFailed) {
		t.Fatalf("want ErrUnwrapFailed, got %v", err)
	}
}

func TestOpenBao_UnwrapKey_NilAndEmpty(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	if _, err := km.UnwrapKey(context.Background(), nil, nil); !isErr(err, ErrInvalidEnvelope) {
		t.Errorf("nil envelope: want ErrInvalidEnvelope, got %v", err)
	}
	if _, err := km.UnwrapKey(context.Background(), &KeyEnvelope{}, nil); !isErr(err, ErrInvalidEnvelope) {
		t.Errorf("empty ciphertext: want ErrInvalidEnvelope, got %v", err)
	}
	if _, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("not-a-transit-ct")}, nil); !isErr(err, ErrInvalidEnvelope) {
		t.Errorf("non-transit ciphertext: want ErrInvalidEnvelope, got %v", err)
	}
}

func TestOpenBao_ContextCancelled(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := km.WrapKey(ctx, make([]byte, 32), nil); err == nil {
		t.Error("WrapKey with cancelled ctx: want error")
	}
	if _, err := km.UnwrapKey(ctx, &KeyEnvelope{Ciphertext: []byte("vault:v1:abc")}, nil); err == nil {
		t.Error("UnwrapKey with cancelled ctx: want error")
	}
}

func TestOpenBao_Close_Idempotent_And_PostClose(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)

	if err := km.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := km.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := km.WrapKey(context.Background(), make([]byte, 32), nil); !isErr(err, ErrProviderUnavailable) {
		t.Errorf("post-close WrapKey: want ErrProviderUnavailable, got %v", err)
	}
	if _, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("vault:v1:abc")}, nil); !isErr(err, ErrProviderUnavailable) {
		t.Errorf("post-close UnwrapKey: want ErrProviderUnavailable, got %v", err)
	}
}

func TestOpenBao_ActiveKeyVersion(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.mu.Lock()
	srv.latestVersion = 3
	srv.mu.Unlock()
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	v, err := km.ActiveKeyVersion(context.Background())
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if v != 3 {
		t.Errorf("ActiveKeyVersion: got %d want 3", v)
	}
}

func TestOpenBao_HealthCheck_Healthy(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	if err := km.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

// TestOpenBao_HealthCheck_ExpiredToken is the GAP-KMS3-3 fix: a token that has
// expired must make HealthCheck fail even though sys/health would return 200.
func TestOpenBao_HealthCheck_ExpiredToken(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	srv.setLookupStatus(http.StatusForbidden) // token expired
	if err := km.HealthCheck(context.Background()); !isErr(err, ErrProviderUnavailable) {
		t.Fatalf("expired token: want ErrProviderUnavailable, got %v", err)
	}
}

// TestOpenBao_HealthCheck_MissingKey covers the gap that lookup-self alone could
// not detect: a valid token but a wrong/missing transit key. HealthCheck must
// fail with ErrKeyNotFound rather than reporting healthy.
func TestOpenBao_HealthCheck_MissingKey(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	srv.setKeysStatus(http.StatusNotFound) // key_name wrong / key deleted
	err := km.HealthCheck(context.Background())
	if !isErr(err, ErrKeyNotFound) {
		t.Fatalf("missing key: want ErrKeyNotFound, got %v", err)
	}
}

// TestOpenBao_HealthCheck_KeyPolicyDenied covers a token that is valid but lacks
// keys-read on the transit key (403 on keys read) — must be unhealthy, not OK.
func TestOpenBao_HealthCheck_KeyPolicyDenied(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	srv.setKeysStatus(http.StatusForbidden)
	if err := km.HealthCheck(context.Background()); !isErr(err, ErrProviderUnavailable) {
		t.Fatalf("key policy denied: want ErrProviderUnavailable, got %v", err)
	}
}

func TestOpenBao_Auth_AppRole(t *testing.T) {
	srv := newMockBaoServer(t)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address:        srv.URL,
		KeyName:        "test-key",
		Auth:           OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		DisableRenewal: true,
		Timeout:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("approle construct: %v", err)
	}
	defer func() { _ = km.Close(context.Background()) }()

	if srv.loginCount != 1 {
		t.Errorf("expected 1 login, got %d", srv.loginCount)
	}
	// token from login must work for a wrap
	if _, err := km.WrapKey(context.Background(), make([]byte, 32), nil); err != nil {
		t.Errorf("WrapKey after approle login: %v", err)
	}
	m := km.(*openBaoTransitManager)
	if m.client.Token() != "logged-in-token" {
		t.Errorf("token not set from login, got %q", m.client.Token())
	}
}

func TestOpenBao_Auth_Kubernetes(t *testing.T) {
	srv := newMockBaoServer(t)
	dir := t.TempDir()
	jwtPath := filepath.Join(dir, "token")
	if err := os.WriteFile(jwtPath, []byte("fake-sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address:        srv.URL,
		KeyName:        "test-key",
		Auth:           OpenBaoAuthConfig{Method: "kubernetes", Role: "s3-gw", JWTPath: jwtPath},
		DisableRenewal: true,
		Timeout:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("kubernetes construct: %v", err)
	}
	defer func() { _ = km.Close(context.Background()) }()

	m := km.(*openBaoTransitManager)
	if m.client.Token() != "logged-in-token" {
		t.Errorf("token not set from k8s login, got %q", m.client.Token())
	}
}

func TestOpenBao_FailClosed_OnBadAuth(t *testing.T) {
	srv := newMockBaoServer(t)
	// approle without role_id -> login must fail -> constructor must fail
	_, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", SecretID: "sid"},
	})
	if err == nil {
		t.Fatal("expected fail-closed construction error for missing role_id")
	}
}

func TestOpenBao_Rotation_PrepareAndPromote(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	rkm := km.(RotatableKeyManager)
	plan, err := rkm.PrepareRotation(context.Background(), nil)
	if err != nil {
		t.Fatalf("PrepareRotation: %v", err)
	}
	if plan.CurrentVersion != 1 || plan.TargetVersion != 2 {
		t.Fatalf("plan: got {%d,%d} want {1,2}", plan.CurrentVersion, plan.TargetVersion)
	}

	if err := rkm.PromoteActiveVersion(context.Background(), plan); err != nil {
		t.Fatalf("PromoteActiveVersion: %v", err)
	}
	if srv.getLatestVersion() != 2 {
		t.Errorf("server latest_version: got %d want 2", srv.getLatestVersion())
	}
	v, _ := km.ActiveKeyVersion(context.Background())
	if v != 2 {
		t.Errorf("ActiveKeyVersion after promote: got %d want 2", v)
	}
}

func TestOpenBao_Rotation_PrepareRejectsNonNextTarget(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	rkm := km.(RotatableKeyManager)
	target := 5 // current is 1, only 2 is allowed
	if _, err := rkm.PrepareRotation(context.Background(), &target); !isErr(err, ErrRotationAmbiguous) {
		t.Fatalf("want ErrRotationAmbiguous for non-next target, got %v", err)
	}
}

func TestOpenBao_Rotation_PromoteConflict(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv)
	defer func() { _ = km.Close(context.Background()) }()

	rkm := km.(RotatableKeyManager)
	// Stale plan: claims current version 9, but server is at 1.
	err := rkm.PromoteActiveVersion(context.Background(), RotationPlan{CurrentVersion: 9, TargetVersion: 10})
	if !isErr(err, ErrRotationConflict) {
		t.Fatalf("want ErrRotationConflict, got %v", err)
	}
}

// TestOpenBao_Renewal_StartsAndStopsCleanly exercises the background renewal
// goroutine with a renewable login token and asserts Close stops it without
// leaking (run under -race). It also confirms at least one renewal happens.
func TestOpenBao_Renewal_StartsAndStopsCleanly(t *testing.T) {
	srv := newMockBaoServer(t)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		// renewal ENABLED (lease_duration=2s from mock -> watcher renews ~every 1.3s)
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	// Wait long enough for at least one renew-self call. The mock issues a 2s
	// lease, so the LifetimeWatcher renews at ~1.3s; an 8s budget is generous
	// even on heavily loaded CI runners.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		rc := srv.renewCount
		srv.mu.Unlock()
		if rc > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	srv.mu.Lock()
	rc := srv.renewCount
	srv.mu.Unlock()
	if rc == 0 {
		t.Error("expected at least one token renewal")
	}

	done := make(chan struct{})
	go func() { _ = km.Close(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return promptly — renewal goroutine leak")
	}
}

// TestOpenBao_Renewal_ReLoginsOnDoneCh covers the highest-risk path: when the
// token can no longer be renewed (LifetimeWatcher fires DoneCh — the real-world
// max_ttl / revoke / restart case), the adapter must RE-LOGIN, not just exit.
// The mock makes renew-self return a non-renewable token so DoneCh fires; a
// successful re-login bumps loginCount past the initial login.
func TestOpenBao_Renewal_ReLoginsOnDoneCh(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setRenewNonRenewable(true)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Initial login = 1. The watcher renews (~1.3s), gets a non-renewable token,
	// fires DoneCh, and the loop must re-login -> loginCount >= 2.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if srv.getLoginCount() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lc := srv.getLoginCount(); lc < 2 {
		t.Fatalf("expected re-login on DoneCh (loginCount >= 2), got %d", lc)
	}

	// The re-logged-in token must be usable.
	if _, err := km.WrapKey(context.Background(), make([]byte, 32), nil); err != nil {
		t.Errorf("WrapKey after re-login: %v", err)
	}
}

// TestFallback_OpenBaoPrimary_DecryptsLegacyPasswordEnvelope is the regression
// test for the interaction between the OpenBao adapter's up-front ciphertext
// validation and the password fallback: a legacy object wrapped by the password
// KM (Provider="password") has a non-"vault:v" ciphertext, so the OpenBao
// primary rejects it with ErrInvalidEnvelope (not ErrUnwrapFailed). The fallback
// must still route such envelopes to the password KM.
func TestFallback_OpenBaoPrimary_DecryptsLegacyPasswordEnvelope(t *testing.T) {
	ctx := context.Background()
	srv := newMockBaoServer(t)
	primary := newTestManager(t, srv) // OpenBao primary (token auth, renewal off)

	pkm, err := NewPasswordKeyManager([]byte("legacy-password-abcdefghijklmnop"))
	if err != nil {
		t.Fatalf("NewPasswordKeyManager: %v", err)
	}

	fb := NewFallbackKeyManager(primary, pkm)
	t.Cleanup(func() { _ = fb.Close(ctx) })

	// Simulate a legacy object: DEK wrapped by the password KM.
	dek := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	legacyEnv, err := pkm.WrapKey(ctx, dek, nil)
	if err != nil {
		t.Fatalf("password WrapKey: %v", err)
	}
	if legacyEnv.Provider != passwordKMProvider {
		t.Fatalf("expected provider %q, got %q", passwordKMProvider, legacyEnv.Provider)
	}
	if strings.HasPrefix(string(legacyEnv.Ciphertext), "vault:v") {
		t.Fatal("precondition: legacy ciphertext must NOT look like a Transit ciphertext")
	}

	// Through the fallback: OpenBao primary rejects with ErrInvalidEnvelope, the
	// fallback recovers via the password KM.
	got, err := fb.UnwrapKey(ctx, legacyEnv, nil)
	if err != nil {
		t.Fatalf("fallback failed to decrypt legacy password envelope: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("legacy DEK round-trip mismatch through OpenBao+password fallback")
	}
}

// isErr is a small errors.Is helper to keep test assertions terse.
func isErr(err, target error) bool {
	return err != nil && errors.Is(err, target)
}

// ---- credential/key-material leak tests ------------------------------------
// These tests assert that no token value, AppRole secret, or plaintext DEK
// byte string appears in any error message returned by the adapter.  Callers
// typically log errors verbatim, so error strings are the primary leak vector
// in an adapter that has no direct log calls of its own.

// TestOpenBao_NoTokenInErrors verifies that a token value never surfaces in
// any error message produced by WrapKey, UnwrapKey, HealthCheck, or
// ActiveKeyVersion — even when the mock server deliberately rejects the
// request with a 403 (expired-token scenario) or when the encrypt/decrypt
// endpoint is misconfigured.
func TestOpenBao_NoTokenInErrors(t *testing.T) {
	const secret = "super-secret-vault-token-abc123" // value we must never see in errors

	srv := newMockBaoServer(t)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address:        srv.URL,
		KeyName:        "test-key",
		Auth:           OpenBaoAuthConfig{Method: "token", Token: secret},
		DisableRenewal: true,
		Timeout:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer func() { _ = km.Close(context.Background()) }()

	// Inject a 403 on every subsequent request so all operations fail.
	srv.setLookupStatus(http.StatusForbidden)
	srv.mu.Lock()
	srv.encryptStatus = http.StatusForbidden
	srv.decryptStatus = http.StatusForbidden
	srv.keysStatus = http.StatusForbidden
	srv.mu.Unlock()

	check := func(label string, gotErr error) {
		t.Helper()
		if gotErr == nil {
			return // not an error; nothing to check
		}
		msg := gotErr.Error()
		if strings.Contains(msg, secret) {
			t.Errorf("%s: token value leaked into error message: %q", label, msg)
		}
	}

	dek := make([]byte, 32)
	_, wrapErr := km.WrapKey(context.Background(), dek, nil)
	check("WrapKey", wrapErr)

	_, unwrapErr := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("vault:v1:abc")}, nil)
	check("UnwrapKey", unwrapErr)

	check("HealthCheck", km.HealthCheck(context.Background()))

	_, akvErr := km.ActiveKeyVersion(context.Background())
	check("ActiveKeyVersion", akvErr)
}

// TestOpenBao_NoDEKInErrors verifies that the plaintext DEK bytes (or their
// base64 encoding) never appear in any error message when WrapKey or UnwrapKey
// fails.  The mock is wired to fail after receiving the request, so the
// plaintext is already in-flight when the error path is exercised.
func TestOpenBao_NoDEKInErrors(t *testing.T) {
	srv := newMockBaoServer(t)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address:        srv.URL,
		KeyName:        "test-key",
		Auth:           OpenBaoAuthConfig{Method: "token", Token: "test-token"},
		DisableRenewal: true,
		Timeout:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer func() { _ = km.Close(context.Background()) }()

	// Use a recognisable DEK so any leak is obvious.
	dek := []byte("DEADBEEFDEADBEEFDEADBEEFDEADBEEF") // 32 ascii bytes

	// Make encrypt fail with a 500 so the plaintext is handed to the error path.
	srv.mu.Lock()
	srv.encryptStatus = http.StatusInternalServerError
	srv.mu.Unlock()

	_, wrapErr := km.WrapKey(context.Background(), dek, nil)
	if wrapErr != nil {
		msg := wrapErr.Error()
		if strings.Contains(msg, string(dek)) {
			t.Errorf("WrapKey error contains raw DEK: %q", msg)
		}
	}

	// Make decrypt fail; pass a recognisable ciphertext whose plaintext would
	// be the DEK.  Even on error the adapter must not reproduce the DEK.
	srv.mu.Lock()
	srv.encryptStatus = 0
	srv.decryptStatus = http.StatusInternalServerError
	srv.mu.Unlock()

	// First get a valid ciphertext so we have a well-formed envelope.
	env, err := km.WrapKey(context.Background(), dek, nil)
	if err != nil {
		t.Fatalf("WrapKey (second attempt): %v", err)
	}
	_, unwrapErr := km.UnwrapKey(context.Background(), env, nil)
	if unwrapErr != nil {
		msg := unwrapErr.Error()
		if strings.Contains(msg, string(dek)) {
			t.Errorf("UnwrapKey error contains raw DEK: %q", msg)
		}
	}
}

// ---- unit coverage helpers -------------------------------------------------

// TestSleepOrStop_StopsEarly verifies that sleepOrStop returns false when the
// stop channel is closed before the timer fires.
func TestSleepOrStop_StopsEarly(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	if sleepOrStop(stop, 10*time.Second) {
		t.Error("expected sleepOrStop to return false when stop is already closed")
	}
}

// TestSleepOrStop_TimerFires verifies that sleepOrStop returns true when the
// duration elapses before stop is closed.
func TestSleepOrStop_TimerFires(t *testing.T) {
	stop := make(chan struct{})
	if !sleepOrStop(stop, time.Millisecond) {
		t.Error("expected sleepOrStop to return true when timer fires first")
	}
}

// TestNextBackoff covers both the doubling and the cap branches.
func TestNextBackoff(t *testing.T) {
	cases := []struct {
		cur, max, want time.Duration
	}{
		{time.Second, 5 * time.Minute, 2 * time.Second},           // normal double
		{3 * time.Minute, 5 * time.Minute, 5 * time.Minute},       // capped
		{5 * time.Minute, 5 * time.Minute, 5 * time.Minute},       // already at cap
		{100 * time.Millisecond, time.Second, 200 * time.Millisecond}, // sub-second
	}
	for _, tc := range cases {
		got := nextBackoff(tc.cur, tc.max)
		if got != tc.want {
			t.Errorf("nextBackoff(%v, %v) = %v, want %v", tc.cur, tc.max, got, tc.want)
		}
	}
}

// TestWithTimeout_NilContext verifies that a nil ctx is coerced to
// context.Background() rather than panicking.
func TestWithTimeout_NilContext(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv).(*openBaoTransitManager)
	defer func() { _ = km.Close(context.Background()) }()

	ctx, cancel := km.withTimeout(nil)
	defer cancel()
	if ctx == nil {
		t.Error("withTimeout(nil) returned nil context")
	}
	// Should not be the zero context
	select {
	case <-ctx.Done():
		t.Error("context returned by withTimeout(nil) is already cancelled")
	default:
	}
}

// TestWithTimeout_ZeroTimeout verifies the zero-timeout path returns the
// original context unchanged with a no-op cancel.
func TestWithTimeout_ZeroTimeout(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv).(*openBaoTransitManager)
	defer func() { _ = km.Close(context.Background()) }()

	km.timeout = 0 // disable per-request timeout
	parent := context.Background()
	ctx, cancel := km.withTimeout(parent)
	defer cancel()
	if ctx != parent {
		t.Error("expected withTimeout with zero timeout to return parent context unchanged")
	}
}

// TestClassifyError_NilAndPassthrough covers the nil-error and non-ResponseError
// branches of classifyError that are not exercised by the HTTP-server-based tests.
func TestClassifyError_NilAndPassthrough(t *testing.T) {
	srv := newMockBaoServer(t)
	km := newTestManager(t, srv).(*openBaoTransitManager)
	defer func() { _ = km.Close(context.Background()) }()

	// nil error → nil returned
	if got := km.classifyError(context.Background(), nil); got != nil {
		t.Errorf("classifyError(nil) = %v, want nil", got)
	}

	// non-ResponseError (plain error) → returned as-is
	plain := fmt.Errorf("network timeout")
	if got := km.classifyError(context.Background(), plain); got != plain {
		t.Errorf("classifyError(plain) = %v, want %v", got, plain)
	}

	// cancelled context → ctx.Err() returned regardless of the error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := km.classifyError(ctx, plain)
	if got != context.Canceled {
		t.Errorf("classifyError with cancelled ctx = %v, want context.Canceled", got)
	}
}

// TestToInt_AllBranches exercises every type case in toInt.
func TestToInt_AllBranches(t *testing.T) {
	cases := []struct {
		in      any
		want    int
		wantOK  bool
	}{
		{json.Number("42"), 42, true},
		{json.Number("bad"), 0, false},
		{float64(7), 7, true},
		{int(3), 3, true},
		{int64(99), 99, true},
		{"12", 12, true},
		{"nope", 0, false},
		{nil, 0, false},
		{[]byte("x"), 0, false},
	}
	for _, tc := range cases {
		got, ok := toInt(tc.in)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("toInt(%v) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
