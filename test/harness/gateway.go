package harness

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/cloud37/s3-encryption-gateway/internal/admin"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/middleware"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/sizecache"
	"github.com/cloud37/s3-encryption-gateway/internal/util"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Gateway represents a running in-process gateway server.
// All test interaction with the gateway should go through the URL field.
type Gateway struct {
	// URL is the base HTTP address of the gateway, e.g. "http://127.0.0.1:41523".
	URL string
	// Addr is the host:port the gateway is listening on.
	Addr string
	// Metrics is the Prometheus registry used by this gateway instance.
	// Conformance tests can query it to assert metric emission.
	Metrics *prometheus.Registry
	// AdminURL is the base HTTP address of the admin listener when
	// WithAdminServer was used, e.g. "http://127.0.0.1:41524".
	// Empty when no admin listener was requested.
	AdminURL string
	// AdminToken is the bearer token for the admin listener.
	// Empty when no admin listener was requested.
	AdminToken       string
	postStageCapture *postStageLogCapture
	postBoundaries   *postBoundaryCapture

	server   *http.Server
	listener net.Listener
	tls      bool
}

type postBoundaryCapture struct {
	mu                           sync.Mutex
	outer, authenticated, routed int
}

// PostObjectBoundaries reports counts only, without request identifiers or data.
func (g *Gateway) PostObjectBoundaries() [3]int {
	if g == nil || g.postBoundaries == nil {
		return [3]int{}
	}
	g.postBoundaries.mu.Lock()
	defer g.postBoundaries.mu.Unlock()
	return [3]int{g.postBoundaries.outer, g.postBoundaries.authenticated, g.postBoundaries.routed}
}

func observePostBoundary(next http.Handler, capture *postBoundaryCapture, boundary int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			capture.mu.Lock()
			switch boundary {
			case 0:
				capture.outer++
			case 1:
				capture.authenticated++
			case 2:
				capture.routed++
			}
			capture.mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

type postStageLogCapture struct {
	mu        sync.Mutex
	stages    []string
	truncated bool
}

func (*postStageLogCapture) Levels() []logrus.Level { return logrus.AllLevels }

func (c *postStageLogCapture) Fire(entry *logrus.Entry) error {
	if entry == nil || entry.Data["operation"] != "PostObject" {
		return nil
	}
	stage, ok := entry.Data["stage"].(string)
	if !ok {
		return nil
	}
	switch stage {
	case "validation", "encryption", "classification", "preparation", "backend", "backend_acquisition", "unknown":
	default:
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stages) < 64 {
		c.stages = append(c.stages, stage)
	} else {
		c.truncated = true
	}
	return nil
}

// PostObjectFailureStages returns only fixed, allowlisted diagnostic stage
// labels. It never returns the original logger records or arbitrary fields.
func (g *Gateway) PostObjectFailureStages() []string {
	if g == nil || g.postStageCapture == nil {
		return nil
	}
	g.postStageCapture.mu.Lock()
	defer g.postStageCapture.mu.Unlock()
	return append([]string(nil), g.postStageCapture.stages...)
}

// PostObjectFailureStagesSince returns only allowlisted stage labels captured
// after the caller's snapshot index, with a consistency flag when the bounded
// buffer has not overflowed.
func (g *Gateway) PostObjectFailureStagesSince(index int) ([]string, bool) {
	if g == nil || g.postStageCapture == nil {
		return nil, false
	}
	g.postStageCapture.mu.Lock()
	defer g.postStageCapture.mu.Unlock()
	if index < 0 || index > len(g.postStageCapture.stages) || g.postStageCapture.truncated {
		return nil, false
	}
	return append([]string(nil), g.postStageCapture.stages[index:]...), true
}

// PostObjectFailureStageCount returns the current count of retained safe stages.
func (g *Gateway) PostObjectFailureStageCount() int {
	if g == nil || g.postStageCapture == nil {
		return 0
	}
	g.postStageCapture.mu.Lock()
	defer g.postStageCapture.mu.Unlock()
	return len(g.postStageCapture.stages)
}

// headObjectOverrideClient wraps an s3.Client and overrides Content-Length in
// HeadObject responses when the provided fn returns a non-nil value.
type headObjectOverrideClient struct {
	s3.Client
	fn func(bucket, key string) *int64
}

type observedResponseWriter struct {
	http.ResponseWriter
	status      int
	allowOrigin string
}

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status == 0 || (w.status >= 100 && w.status < 200 && (status >= 200 || status == http.StatusSwitchingProtocols)) {
		w.status = status
		w.allowOrigin = w.Header().Get("Access-Control-Allow-Origin")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 || (w.status >= 100 && w.status < 200) {
		w.status = http.StatusOK
		w.allowOrigin = w.Header().Get("Access-Control-Allow-Origin")
	}
	return w.ResponseWriter.Write(body)
}

func (w *observedResponseWriter) Flush() {
	if w.status == 0 || (w.status >= 100 && w.status < 200) {
		w.status = http.StatusOK
		w.allowOrigin = w.Header().Get("Access-Control-Allow-Origin")
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *observedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *observedResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func observeRequests(next http.Handler, observer func(RequestObservation)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed := &observedResponseWriter{ResponseWriter: w}
		next.ServeHTTP(observed, r)
		status := observed.status
		if status == 0 {
			status = http.StatusOK
		}
		observer(RequestObservation{
			Method: r.Method, Path: r.URL.Path, Status: status,
			Origin:                      r.Header.Get("Origin"),
			AccessControlRequestMethod:  r.Header.Get("Access-Control-Request-Method"),
			AccessControlRequestHeaders: r.Header.Get("Access-Control-Request-Headers"),
			AuthorizationPresent:        len(r.Header.Values("Authorization")) > 0,
			AllowOrigin:                 observed.allowOrigin,
		})
	})
}

func (c *headObjectOverrideClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	meta, err := c.Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil || meta == nil {
		return meta, err
	}
	if override := c.fn(bucket, key); override != nil {
		cp := make(map[string]string, len(meta)+1)
		for k, v := range meta {
			cp[k] = v
		}
		cp["Content-Length"] = fmt.Sprintf("%d", *override)
		return cp, nil
	}
	return meta, nil
}

// StartGateway starts an in-process gateway configured to talk to inst and
// registers t.Cleanup to shut it down. The backend named in inst is already
// running; this function only starts the gateway process.
func StartGateway(t *testing.T, inst provider.Instance, opts ...Option) *Gateway {
	t.Helper()

	o := newOptions()
	o.encryptionPassword = "test-encryption-password-123456"
	o.logLevel = "error"
	for _, opt := range opts {
		opt(o)
	}

	// Build the config from the provider instance.
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		LogLevel:            o.logLevel,
		AllowBucketCreation: o.allowBucketCreation,
		Backend: config.BackendConfig{
			Endpoint:     inst.Endpoint,
			Region:       inst.Region,
			AccessKey:    inst.AccessKey,
			SecretKey:    inst.SecretKey,
			Provider:     inst.ProviderName,
			UseSSL:       false,
			UsePathStyle: true,
		},
		Encryption: config.EncryptionConfig{
			Password: o.encryptionPassword,
			KDF: config.KDFConfig{
				Algorithm: o.kdfAlgorithm,
				PBKDF2: config.PBKDF2Config{
					Iterations: o.pbkdf2Iterations,
				},
				Argon2id: o.argon2idParams,
			},
		},
	}
	cfg.TLS.Enabled = o.useTLS
	cfg.Encryption.KDF.DecryptLimits = config.KDFDecryptLimitsConfig{PBKDF2: config.PBKDF2DecryptLimitsConfig{MaxIterations: o.kdfDecryptLimits.PBKDF2MaxIterations}, Argon2id: config.Argon2idDecryptLimitsConfig{MaxTime: o.kdfDecryptLimits.Argon2idMaxTime, MaxMemory: o.kdfDecryptLimits.Argon2idMaxMemory, MaxThreads: o.kdfDecryptLimits.Argon2idMaxThreads}}

	// Apply WithAuth credentials before extraConfig so extraConfig can override.
	if len(o.authCredentials) > 0 {
		cfg.Auth.Credentials = o.authCredentials
	}
	// Apply optional config mutator last.
	if o.extraConfig != nil {
		o.extraConfig(cfg)
	}
	if err := cfg.Backend.ValidatePostSettings(); err != nil {
		t.Fatalf("harness.StartGateway: invalid backend settings: %v", err)
	}
	if err := cfg.LoadCredentialSources(); err != nil {
		t.Fatalf("harness.StartGateway: load credential sources: %v", err)
	}
	// Convenience option is applied after the mutator when explicitly set.
	if o.corsMode != "" {
		cfg.CORS.Mode = o.corsMode
	}
	// StartGateway constructs Config directly rather than through LoadConfig.
	// Preserve production defaults so the shared SEC-49 manager has a usable
	// aggregate budget unless a test explicitly configures one.
	if cfg.Server.MaxVerifiedSpoolBytes <= 0 {
		cfg.Server.MaxVerifiedSpoolBytes = config.DefaultMaxVerifiedSpoolBytes
	}
	if cfg.Server.MaxAggregateSpoolBytes <= 0 {
		cfg.Server.MaxAggregateSpoolBytes = config.DefaultMaxAggregateSpoolBytes
	}

	// Network listener on a random free port.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatalf("harness.StartGateway: listen: %v", err)
	}

	addr := listener.Addr().String()
	scheme := "http"
	serveListener := listener
	if o.useTLS {
		cert, certErr := gatewayTestCertificate()
		if certErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create TLS certificate: %v", certErr)
		}
		serveListener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		scheme = "https"
	}
	url := scheme + "://" + addr

	// Logger.
	logger := logrus.New()
	postStageCapture := &postStageLogCapture{}
	logger.AddHook(postStageCapture)
	if o.accessLogOutput != nil {
		logger.SetOutput(o.accessLogOutput)
	} else {
		logger.SetOutput(io.Discard)
	}
	if lvl, err := logrus.ParseLevel(o.logLevel); err == nil {
		logger.SetLevel(lvl)
	} else {
		logger.SetLevel(logrus.ErrorLevel)
	}

	// Initialize IP extractor with trusted proxies (V1.0-SEC-6).
	// This ensures client IP extraction honors trusted proxy configuration
	// and prevents X-Forwarded-For header spoofing.
	ipExtractor, err := setGatewayTrustedExtractor(cfg)
	if err != nil {
		listener.Close()
		t.Fatalf("harness.StartGateway: invalid trusted proxies configuration: %v", err)
	}

	// Prometheus registry (isolated per test to avoid cross-test pollution).
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// S3 backend client.
	// V0.6-PERF-2: use NewClientFactory so the retry policy and optional
	// fault-injection transport are both wired in.
	factoryOpts := []s3.ClientFactoryOption{s3.WithMetrics(m)}
	if o.backendTransport != nil {
		factoryOpts = append(factoryOpts, s3.WithHTTPTransport(o.backendTransport))
	}
	s3Client, err := s3.NewBackendClient(&cfg.Backend, factoryOpts...)
	if err != nil {
		listener.Close()
		t.Fatalf("harness.StartGateway: create S3 client: %v", err)
	}
	if o.headObjectOverride != nil {
		s3Client = &headObjectOverrideClient{Client: s3Client, fn: o.headObjectOverride}
	}

	// Encryption engine.
	encryptionEngine, err := crypto.NewEngineWithOpts(
		[]byte(o.encryptionPassword),
		crypto.WithPBKDF2Iterations(o.pbkdf2Iterations),
		crypto.WithChunking(o.chunkedMode),
		backendProviderOption(cfg),
		crypto.WithKDFAlgorithm(o.kdfAlgorithm),
		crypto.WithArgon2idParams(o.argon2idParams.Time, o.argon2idParams.Memory, o.argon2idParams.Threads),
		crypto.WithKDFLimits(o.kdfDecryptLimits),
	)
	if err != nil {
		listener.Close()
		t.Fatalf("harness.StartGateway: create encryption engine: %v", err)
	}
	// V1.0-CRYPTO-3: wire metadata encryption key if configured.
	if len(o.metadataEncryptionKey) > 0 {
		crypto.SetMetadataKey(encryptionEngine, o.metadataEncryptionKey)
	}

	// Wire the KeyManager into the encryption engine so that regular PUT/GET
	// operations use envelope encryption (KMS wrap/unwrap) and not just the
	// password-derived key. Without this, WithKeyManager only affects the MPU
	// path; the default engine would silently fall back to password-based mode.
	if o.keyManager != nil {
		crypto.SetKeyManager(encryptionEngine, o.keyManager)
	}

	// Encrypted-MPU: if valkeyAddr is set without an explicit mpuStore,
	// construct a ValkeyStateStore (plaintext allowed — test containers).
	if o.valkeyAddr != "" && o.mpuStore == nil {
		store, storeErr := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
			Addr:                   o.valkeyAddr,
			EncryptState:           config.BoolPtr(false),
			InsecureAllowPlaintext: true,
			TLS:                    config.ValkeyTLSConfig{Enabled: false},
			TTLSeconds:             3600,
			DialTimeout:            2 * time.Second,
			ReadTimeout:            1 * time.Second,
			WriteTimeout:           1 * time.Second,
			PoolSize:               4,
		}, nil, "")
		if storeErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create Valkey state store (%s): %v", o.valkeyAddr, storeErr)
		}
		o.mpuStore = store
		t.Cleanup(func() { _ = store.Close() })
	}
	if config.EffectiveCORSMode(cfg.CORS.Mode) == "gateway" && o.mpuStore == nil {
		listener.Close()
		t.Fatalf("harness.StartGateway: gateway CORS requires a shared Valkey-backed state store; configure WithValkeyAddr")
	}
	if config.EffectiveCORSMode(cfg.CORS.Mode) == "gateway" && o.valkeyAddr == "" {
		listener.Close()
		t.Fatalf("harness.StartGateway: gateway CORS requires WithValkeyAddr; in-memory CORS state is not supported")
	}
	if config.EffectiveCORSMode(cfg.CORS.Mode) == "gateway" {
		_, storeErr := gatewayCORSValkeyStore(o.mpuStore)
		if storeErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: %v", storeErr)
		}
	}
	// Encrypted-MPU: if a bucket glob is configured, build a PolicyManager
	// with EncryptMultipartUploads=true for that glob (unless caller already
	// provided one).
	if o.encryptedMPUBucket != "" && o.policyManager == nil {
		policyDir := t.TempDir()
		policyYAML := fmt.Sprintf("id: harness-enc-mpu\nbuckets:\n  - %q\nencrypt_multipart_uploads: true\n",
			o.encryptedMPUBucket)
		policyPath := filepath.Join(policyDir, "policy.yaml")
		if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: write MPU policy file: %v", err)
		}
		pm := config.NewPolicyManager()
		if err := pm.LoadPolicies([]string{policyPath}); err != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: load MPU policy: %v", err)
		}
		o.policyManager = pm
	}

	// When encrypted MPU is active a KeyManager is required for DEK wrap/unwrap.
	// Default to the password-derived KeyManager if none was supplied.
	if o.mpuStore != nil && o.keyManager == nil {
		km, kmErr := crypto.NewPasswordKeyManager(
			[]byte(o.encryptionPassword),
			crypto.WithPasswordKMPBKDF2(o.pbkdf2Iterations),
			crypto.WithPasswordKMKDFLimits(o.kdfDecryptLimits),
		)
		if kmErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create password KeyManager: %v", kmErr)
		}
		o.keyManager = km
	}

	// One manager is shared by authentication and streaming handlers so tests
	// exercise the same aggregate accounting as production.
	spoolManager, spoolLimits := newGatewaySpoolAccounting(cfg, m)
	// API handler.
	handler := api.NewHandlerWithFeatures(
		s3Client, encryptionEngine, logger, m,
		o.keyManager, nil, o.auditLogger, cfg, o.policyManager,
	).WithSpoolManager(spoolManager).WithSpoolLimitSource(spoolLimits)
	if o.clientAcquisitionObserver != nil {
		handler.WithClientAcquisitionObserver(o.clientAcquisitionObserver)
	}
	if o.backendTransport != nil {
		handler.WithProxyTransport(o.backendTransport)
	}
	if o.cacheOverride != nil {
		handler.WithCache(o.cacheOverride)
	} else if cfg.Cache.Enabled {
		handler.WithCache(cache.NewMemoryCache(cfg.Cache.MaxSize, cfg.Cache.MaxItems, cfg.Cache.DefaultTTL))
	}
	if o.mpuStore != nil {
		handler.WithMPUStateStore(o.mpuStore)
		stopHealthCheck := mpu.StartHealthCheck(context.Background(), o.mpuStore, cfg.MultipartState.Valkey.HealthCheckInterval, m.SetMPUValkeyUp)
		t.Cleanup(stopHealthCheck)
		// Wire the ListObjects size cache, sharing the Valkey connection pool.
		cfg.ListSizeTranslate.Enabled = true
		if vs, ok := o.mpuStore.(*mpu.ValkeyStateStore); ok {
			sc := sizecache.NewValkeySizeCache(vs.Client())
			handler.WithSizeCache(sc)
		}
	}
	var corsStore api.CORSStore
	if config.EffectiveCORSMode(cfg.CORS.Mode) == "gateway" {
		valkeyStore, _ := gatewayCORSValkeyStore(o.mpuStore)
		corsStore = api.NewValkeyCORSStore(valkeyStore.Client())
		handler.WithCORSStore(corsStore)
	}

	// Router.
	// Match the production router's literal S3 object-key handling.
	router := mux.NewRouter().SkipClean(true)
	router.Handle("/metrics", m.Handler()).Methods("GET")
	handler.RegisterRoutes(router)

	// Middleware. Wrap in the same order as cmd/server/main.go: the code below
	// applies each outer wrapper after its inner handler has been constructed.
	postBoundaries := &postBoundaryCapture{}
	httpHandler := observePostBoundary(middleware.StripBucketTrailingSlash(router), postBoundaries, 2)
	httpHandler = middleware.LoggingMiddleware(logger, &cfg.Logging)(httpHandler)
	httpHandler = middleware.SecurityHeadersMiddleware(cfg.Server.ForceHTTPS)(httpHandler)
	if cfg.Tracing.Enabled {
		httpHandler = middleware.TracingMiddleware(cfg.Tracing.RedactSensitive, ipExtractor)(httpHandler)
	}
	if cfg.RateLimit.Enabled {
		rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.Limit, cfg.RateLimit.Window, logger)
		t.Cleanup(rateLimiter.Stop)
		httpHandler = middleware.RateLimitMiddleware(rateLimiter)(httpHandler)
	}

	// Wire auth middleware if credentials are configured (V1.0-AUTH-1).
	if gatewayCredentialsConfigured(cfg) {
		credStore, credErr := newGatewayCredentialStore(cfg)
		if credErr != nil {
			listener.Close()
			t.Fatalf("harness.StartGateway: create credential store: %v", credErr)
		}
		httpHandler = api.AuthorizationMiddleware(cfg.ProxiedBucket, o.auditLogger)(httpHandler)
		httpHandler = observePostBoundary(httpHandler, postBoundaries, 1)
		clockSkew := cfg.Auth.ClockSkewTolerance
		if clockSkew <= 0 {
			clockSkew = 5 * time.Minute
		}
		httpHandler = api.AuthMiddleware(credStore, clockSkew, logger, o.auditLogger, cfg.Auth.AllowLegacySignatureV2, spoolManager, spoolLimits)(httpHandler)
	}
	if config.EffectiveCORSMode(cfg.CORS.Mode) == "gateway" {
		httpHandler = api.CORSMiddleware(cfg.CORS, corsStore, logger)(httpHandler)
	}
	httpHandler = middleware.RecoveryMiddleware(logger)(httpHandler)
	httpHandler = observePostBoundary(httpHandler, postBoundaries, 0)
	if o.requestObserver != nil {
		httpHandler = observeRequests(httpHandler, o.requestObserver)
	}

	// HTTP server.
	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	go func() {
		if err := server.Serve(serveListener); err != nil && err != http.ErrServerClosed {
			t.Logf("harness gateway server error: %v", err)
		}
	}()

	// Wait for the gateway to be ready.
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		select {
		case <-waitCtx.Done():
			listener.Close()
			t.Fatal("harness.StartGateway: timeout waiting for gateway to become ready")
		default:
			readyClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: o.useTLS}}} // #nosec G402 -- the test-only TLS certificate is self-signed
			resp, err := readyClient.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					goto ready
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

ready:
	gw := &Gateway{
		URL:              url,
		Addr:             addr,
		Metrics:          reg,
		postStageCapture: postStageCapture,
		postBoundaries:   postBoundaries,
		server:           server,
		listener:         listener,
		tls:              o.useTLS,
	}

	// Optional admin listener — wire when WithAdminServer was requested.
	if o.adminEnabled {
		adminCfg := config.AdminConfig{
			Enabled: true,
			Address: "127.0.0.1:0",
			Auth: config.AdminAuthConfig{
				Type:  "bearer",
				Token: o.adminToken,
			},
			RateLimit: config.AdminRateLimitConfig{RequestsPerMinute: 120},
			Profiling: config.AdminProfilingConfig{
				Enabled:               o.adminProfiling,
				MaxConcurrentProfiles: 4,
				MaxProfileSeconds:     60,
			},
		}
		adminSrv := admin.NewServer(adminCfg, logger)
		if o.adminProfiling {
			admin.RegisterPprofRoutes(
				adminSrv.Mux(),
				adminCfg.Profiling,
				m,   // *metrics.Metrics satisfies ProfilingMetrics
				nil, // audit logger — nil OK in tests (checked inside handler)
				logger,
			)
		}
		// Bind to a random loopback port before Start so we can read the address.
		adminListener, adminErr := net.Listen("tcp", "127.0.0.1:0")
		if adminErr != nil {
			t.Fatalf("harness: admin listener: %v", adminErr)
		}
		adminAddr := adminListener.Addr().String()
		adminListener.Close() // release so admin.Server.Start can re-bind
		// Override cfg address with the free port we found.
		adminCfg.Address = adminAddr

		// Rebuild server with the correct address.
		adminSrv2 := admin.NewServer(adminCfg, logger)
		if o.adminProfiling {
			admin.RegisterPprofRoutes(
				adminSrv2.Mux(),
				adminCfg.Profiling,
				m,
				nil,
				logger,
			)
		}
		go func() {
			if startErr := adminSrv2.Start(context.Background()); startErr != nil {
				t.Logf("harness admin server error: %v", startErr)
			}
		}()
		// Wait for admin listener to be ready.
		adminCtx, adminCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer adminCancel()
		adminUp := false
		for !adminUp {
			select {
			case <-adminCtx.Done():
				t.Fatal("harness: timeout waiting for admin server to start")
			default:
			}
			conn, dialErr := net.DialTimeout("tcp", adminAddr, 50*time.Millisecond)
			if dialErr == nil {
				conn.Close()
				adminUp = true
			}
			time.Sleep(10 * time.Millisecond)
		}
		gw.AdminURL = "http://" + adminAddr
		gw.AdminToken = o.adminToken
		t.Cleanup(func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutCancel()
			_ = adminSrv2.Shutdown(shutCtx)
		})
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx) //nolint:errcheck
		listener.Close()
	})

	return gw
}

func newGatewayCredentialStore(cfg *config.Config) (*api.StaticCredentialStore, error) {
	resolved := cfg.ResolvedCredentials()
	defer func() {
		for i := range resolved {
			resolved[i].SecretKey = ""
			resolved[i].SessionToken = ""
		}
	}()
	return api.NewStaticCredentialStore(resolved)
}

func gatewayCredentialsConfigured(cfg *config.Config) bool {
	return cfg != nil && len(cfg.Auth.Credentials) > 0
}

func newGatewayIPExtractor(cfg *config.Config) (*util.IPExtractor, error) {
	if cfg == nil {
		return util.NewIPExtractor(nil)
	}
	return util.NewIPExtractor(append([]string(nil), cfg.Server.TrustedProxies...))
}

func setGatewayTrustedExtractor(cfg *config.Config) (*util.IPExtractor, error) {
	extractor, err := newGatewayIPExtractor(cfg)
	if err != nil {
		return nil, err
	}
	api.SetIPExtractor(extractor)
	middleware.SetIPExtractor(extractor)
	return extractor, nil
}

func newGatewaySpoolAccounting(cfg *config.Config, observer *metrics.Metrics) (api.SpoolManager, *api.SpoolLimitSource) {
	capacity := int64(config.DefaultMaxAggregateSpoolBytes)
	directory := ""
	if cfg != nil {
		if cfg.Server.MaxAggregateSpoolBytes > 0 {
			capacity = cfg.Server.MaxAggregateSpoolBytes
		}
		directory = cfg.Server.SpoolDirectory
	}
	manager := api.NewSpoolManager(capacity, directory, observer)
	limits := api.NewSpoolLimitSource(api.SpoolLimitsForConfig(cfg))
	return manager, limits
}

// ValidateGatewayCORSStateStore is an internal test seam for asserting that
// gateway mode cannot bind CORS to a process-local or unrelated store.
func ValidateGatewayCORSStateStore(store mpu.StateStore) error {
	_, err := gatewayCORSValkeyStore(store)
	return err
}

func gatewayCORSValkeyStore(store mpu.StateStore) (*mpu.ValkeyStateStore, error) {
	valkeyStore, ok := store.(*mpu.ValkeyStateStore)
	if !ok || valkeyStore == nil {
		return nil, fmt.Errorf("gateway CORS requires a shared Valkey-backed MPU state store")
	}
	value := reflect.ValueOf(valkeyStore.Client())
	if !value.IsValid() || ((value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface) && value.IsNil()) {
		return nil, fmt.Errorf("gateway CORS requires a non-nil shared Valkey client")
	}
	return valkeyStore, nil
}

// HTTPClient returns a plain *http.Client suitable for issuing requests to the
// gateway. The client has a 5-minute timeout so large-object conformance tests
// (e.g. 400 MiB encrypted MPU downloads over slower public backends) do not
// abort mid-stream because of a client-side deadline.  The overall test-run
// timeout is still governed by go test's -timeout flag.
func (g *Gateway) HTTPClient() *http.Client {
	transport := &http.Transport{}
	if g.tls {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test-only self-signed certificate
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: transport}
}

func gatewayTestCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "s3-encryption-gateway test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}
