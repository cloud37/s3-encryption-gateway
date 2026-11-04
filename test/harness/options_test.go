package harness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func TestNewOptions_DefaultAndOverrideKDFLimits(t *testing.T) {
	o := newOptions()
	if o.kdfDecryptLimits != crypto.DefaultKDFLimits() {
		t.Fatalf("default limits = %+v, want %+v", o.kdfDecryptLimits, crypto.DefaultKDFLimits())
	}
	o.kdfDecryptLimits = crypto.KDFLimits{PBKDF2MaxIterations: 100000, Argon2idMaxTime: 1, Argon2idMaxMemory: 1, Argon2idMaxThreads: 1}
	if o.kdfDecryptLimits.PBKDF2MaxIterations != 100000 || o.kdfDecryptLimits.Argon2idMaxMemory != 1 {
		t.Fatalf("explicit override was not retained: %+v", o.kdfDecryptLimits)
	}
}

func TestGH353RequestObserverCapturesWireArrivalWithoutSecrets(t *testing.T) {
	var mu sync.Mutex
	var got []RequestObservation
	server := httptest.NewServer(observeRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "https://allowed.example")
		w.WriteHeader(http.StatusNoContent)
	}), func(observation RequestObservation) { mu.Lock(); got = append(got, observation); mu.Unlock() }))
	defer server.Close()

	preflight, err := http.NewRequest(http.MethodOptions, server.URL+"/bucket/object?X-Amz-Signature=must-not-be-recorded", nil)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Header.Set("Origin", "https://allowed.example")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "x-gh353-denied")
	preflight.Header.Set("Authorization", "must-not-be-recorded")
	response, err := server.Client().Do(preflight)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	post, err := http.NewRequest(http.MethodPost, server.URL+"/bucket/object?secret-query=must-not-be-recorded", nil)
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Origin", "https://denied.example")
	post.Header.Set("Authorization", "must-not-be-recorded")
	response, err = server.Client().Do(post)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observations=%d want 2", len(got))
	}
	if got[0] != (RequestObservation{Method: http.MethodOptions, Path: "/bucket/object", Status: http.StatusForbidden, Origin: "https://allowed.example", AccessControlRequestMethod: "POST", AccessControlRequestHeaders: "x-gh353-denied", AuthorizationPresent: true}) {
		t.Fatalf("preflight observation contains wrong or unsafe fields: %+v", got[0])
	}
	if got[1] != (RequestObservation{Method: http.MethodPost, Path: "/bucket/object", Status: http.StatusNoContent, Origin: "https://denied.example", AuthorizationPresent: true, AllowOrigin: "https://allowed.example"}) {
		t.Fatalf("POST observation mismatch: %+v", got[1])
	}
	serialized := fmt.Sprintf("%+v %+v", got[0], got[1])
	if strings.Contains(serialized, "must-not-be-recorded") {
		t.Fatal("request observer retained authorization or query secrets")
	}
}

func TestGH353RequestObserverRetainsFinalStatusAfterContinue(t *testing.T) {
	var got []RequestObservation
	server := httptest.NewServer(observeRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusContinue)
		w.Header().Set("Access-Control-Allow-Origin", "https://final.example")
		w.WriteHeader(http.StatusNoContent)
	}), func(observation RequestObservation) { got = append(got, observation) }))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/bucket")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(got) != 1 || got[0].Status != http.StatusNoContent || got[0].AllowOrigin != "https://final.example" {
		t.Fatalf("observer retained interim status or headers rather than the final wire response: %+v", got)
	}
}

func TestGH353PostStageCaptureAllowlistAndBound(t *testing.T) {
	capture := &postStageLogCapture{}
	for _, stage := range []string{"backend", "classification", "untrusted-stage"} {
		_ = capture.Fire(&logrus.Entry{Data: logrus.Fields{"operation": "PostObject", "stage": stage, "message": "secret-canary"}})
	}
	gw := &Gateway{postStageCapture: capture}
	if got := gw.PostObjectFailureStageCount(); got != 2 {
		t.Fatalf("retained stage count=%d want allowlisted count 2", got)
	}
	stages := gw.PostObjectFailureStages()
	if len(stages) != 2 || stages[0] != "backend" || stages[1] != "classification" {
		t.Fatalf("capture retained unallowlisted or misordered stages: %v", stages)
	}
	since, valid := gw.PostObjectFailureStagesSince(1)
	if !valid || len(since) != 1 || since[0] != "classification" {
		t.Fatalf("stage delta=%v valid=%t", since, valid)
	}
	if _, valid := gw.PostObjectFailureStagesSince(-1); valid {
		t.Fatal("negative snapshot index was accepted")
	}
	overflow := &postStageLogCapture{}
	for range 70 {
		_ = overflow.Fire(&logrus.Entry{Data: logrus.Fields{"operation": "PostObject", "stage": "backend"}})
	}
	if _, valid := (&Gateway{postStageCapture: overflow}).PostObjectFailureStagesSince(0); valid {
		t.Fatal("overflowed stage snapshot was presented as complete")
	}
	if strings.Contains(fmt.Sprint(stages), "secret-canary") || strings.Contains(fmt.Sprint(stages), "untrusted-stage") {
		t.Fatal("stage capture exposed untrusted logger fields")
	}
}

func TestGH353GatewayConfigResolutionMatchesProductionCredentialSources(t *testing.T) {
	t.Setenv("GH353_HARNESS_SECRET", "resolved-secret")
	t.Setenv("GH353_HARNESS_TOKEN", "resolved-session-token")
	t.Setenv("GW_CRED_0_ACCESS_KEY", "")
	expires := "2030-01-02T03:04:05Z"
	deadline, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Auth: config.AuthConfig{Credentials: []config.GatewayCredential{{
		AccessKey: "configured", SecretKeyEnv: "GH353_HARNESS_SECRET", SessionTokenEnv: "GH353_HARNESS_TOKEN",
		ExpiresAt: &deadline, Buckets: []string{"bucket"},
	}}}}
	store, err := newGatewayCredentialStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := store.Lookup("configured")
	if err != nil || resolved.SecretKey != "resolved-secret" || resolved.SessionToken != "resolved-session-token" {
		t.Fatalf("resolved credentials do not match production source handling: credential=%+v err=%v", resolved, err)
	}
	if cfg.Auth.Credentials[0].SecretKey != "" || cfg.Auth.Credentials[0].SessionToken != "" {
		t.Fatal("credential resolution mutated the source config")
	}
}

func TestGH353GatewayLoadsCredentialFileAndEnablesAuthFromResolvedConfig(t *testing.T) {
	t.Setenv("AUTH_CREDENTIALS_FILE", "")
	t.Setenv("GW_CRED_0_ACCESS_KEY", "")
	secretPath := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(secretPath, []byte("- access_key: file-access\n  secret_key: file-secret\n  buckets: [bucket]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_CREDENTIALS_FILE", secretPath)
	cfg := &config.Config{}
	if err := cfg.LoadCredentialSources(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Auth.Credentials) != 1 || !gatewayCredentialsConfigured(cfg) {
		t.Fatalf("credential-file source did not activate auth: configured=%t count=%d", gatewayCredentialsConfigured(cfg), len(cfg.Auth.Credentials))
	}
	store, err := newGatewayCredentialStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Lookup("file-access")
	if err != nil || credential.SecretKey != "file-secret" {
		t.Fatalf("credential-file source was not resolved into auth store: credential=%+v err=%v", credential, err)
	}
}

func TestGH353GatewayLoadsIndexedEnvironmentCredentials(t *testing.T) {
	t.Setenv("AUTH_CREDENTIALS_FILE", "")
	t.Setenv("GW_CRED_0_ACCESS_KEY", "indexed-access")
	t.Setenv("GW_CRED_0_SECRET_KEY", "indexed-secret")
	t.Setenv("GW_CRED_0_BUCKETS", "bucket")
	t.Setenv("GW_CRED_1_ACCESS_KEY", "indexed-session-access")
	t.Setenv("GW_CRED_1_SECRET_KEY", "indexed-session-secret")
	t.Setenv("GW_CRED_1_SESSION_TOKEN", "indexed-session-token")
	t.Setenv("GW_CRED_1_EXPIRES_AT", "2030-01-02T03:04:05Z")
	t.Setenv("GW_CRED_1_BUCKETS", "bucket")
	t.Setenv("GW_CRED_2_ACCESS_KEY", "")
	cfg := &config.Config{}
	if err := cfg.LoadCredentialSources(); err != nil {
		t.Fatal(err)
	}
	if !gatewayCredentialsConfigured(cfg) || len(cfg.Auth.Credentials) != 2 {
		t.Fatalf("indexed environment source did not enable auth: %+v", cfg.Auth.Credentials)
	}
	store, err := newGatewayCredentialStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Lookup("indexed-access")
	if err != nil || credential.SecretKey != "indexed-secret" {
		t.Fatalf("indexed environment source missing from credential store: credential=%+v err=%v", credential, err)
	}
	session, err := store.Lookup("indexed-session-access")
	if err != nil || session.SecretKey != "indexed-session-secret" || session.SessionToken != "indexed-session-token" || session.ExpiresAt == nil || session.ExpiresAt.Format(time.RFC3339) != "2030-01-02T03:04:05Z" {
		t.Fatalf("indexed session source missing from credential store: credential=%+v err=%v", session, err)
	}
}

func TestGH353GatewayIPExtractorUsesConfigTrustSnapshot(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"192.0.2.0/24"}}}
	extractor, err := newGatewayIPExtractor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.TrustedProxies[0] = "198.51.100.0/24"
	request := httptest.NewRequest("GET", "http://gateway.example/", nil)
	request.RemoteAddr = "192.0.2.4:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	if !extractor.IsHTTPSRequest(request) {
		t.Fatal("extractor did not retain the original trusted-proxy config snapshot")
	}
	if _, err := newGatewayIPExtractor(&config.Config{Server: config.ServerConfig{TrustedProxies: []string{"not-a-cidr"}}}); err == nil {
		t.Fatal("invalid trusted-proxy CIDR unexpectedly produced an extractor")
	}
}

func TestGH353GatewaySpoolAccountingUsesOneSharedLimitSnapshot(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{
		MaxAggregateSpoolBytes: 4096,
		MaxVerifiedSpoolBytes:  2048,
		MaxPartBuffer:          1024,
	}}
	manager, limits := newGatewaySpoolAccounting(cfg, nil)
	if manager == nil || limits == nil || limits.Limits() != (api.SpoolLimits{Global: 2048, Part: 1024}) {
		t.Fatalf("manager=%T limits=%+v", manager, limits)
	}
	if cfg.Server.MaxAggregateSpoolBytes != 4096 {
		t.Fatal("spool manager capacity setup modified config")
	}
}
