package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	miniredisserver "github.com/alicebob/miniredis/v2/server"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	mpupkg "github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestInitTracing_Stdout(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Exporter:       "stdout",
		SamplingRatio:  1.0,
	}

	tp, err := InitTracing(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	// Verify tracer provider was set globally
	tracer := otel.Tracer("test")
	require.NotNil(t, tracer)
}

func TestConfigApplier_AllowBucketCreationUpdatesLiveHandler(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{AllowBucketCreation: true}
	h := api.NewHandler(nil, nil, logrus.New(), nil)
	a := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, oldCfg, nil, nil)
	a.SetManagementGate(h)
	if err := a.ApplyConfigChanges(oldCfg, newCfg); err != nil {
		t.Fatal(err)
	}
	if !h.AllowBucketCreation() {
		t.Fatal("live management gate did not update")
	}
}

func TestConfigChangeApplier_RejectsCORSHotReloadBeforeMutation(t *testing.T) {
	oldCfg := &config.Config{LogLevel: "info"}
	newCfg := &config.Config{LogLevel: "debug", CORS: config.CORSConfig{Mode: "gateway"}}
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	a := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, nil)
	require.ErrorContains(t, a.ApplyConfigChanges(oldCfg, newCfg), "cors settings cannot be changed")
	require.Equal(t, logrus.InfoLevel, logger.GetLevel(), "CORS reload rejection must precede unrelated mutations")
}

func TestGatewayCORS_PersistenceWarningIsAdvisory(t *testing.T) {
	logger := logrus.New()
	var output strings.Builder
	logger.SetOutput(&output)
	logger.SetLevel(logrus.DebugLevel)
	client := newPersistenceProbeClient(false, false, false)
	logCORSValkeyPersistence(client, logger)
	require.Equal(t, int64(1), client.pings.Load(), "healthy Valkey protocol client is probed before advisory persistence query")
	require.Contains(t, output.String(), "DURABILITY WARNING")
	require.Equal(t, int64(1), client.infoCalls.Load())
	require.Equal(t, int64(1), client.configCalls.Load())
}

func TestGatewayCORS_PersistenceCheckUsesHealthyPingAndRunsAdvisoryQuery(t *testing.T) {
	client := newPersistenceProbeClient(false, false, true)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, known, infoErr, configErr := corsValkeyPersistenceStateForClient(ctx, client)
	require.False(t, known)
	require.NoError(t, infoErr)
	require.NoError(t, configErr)
	require.Equal(t, int64(1), client.infoCalls.Load())
	require.Equal(t, int64(1), client.configCalls.Load())
	logCORSValkeyPersistence(client, logger)
	require.Equal(t, int64(1), client.pings.Load())
	require.Equal(t, int64(2), client.infoCalls.Load())
	require.Equal(t, int64(2), client.configCalls.Load())
}

func TestGatewayCORS_PersistenceUnknownIsAdvisoryOnReachableValkey(t *testing.T) {
	logger := logrus.New()
	var output strings.Builder
	logger.SetOutput(&output)
	logger.SetLevel(logrus.DebugLevel)
	client := newPersistenceProbeClient(false, false, true)
	logCORSValkeyPersistence(client, logger)
	require.Equal(t, int64(1), client.pings.Load())
	require.Equal(t, int64(1), client.infoCalls.Load())
	require.Equal(t, int64(1), client.configCalls.Load())
	require.Contains(t, output.String(), "DURABILITY WARNING")
	require.NotContains(t, output.String(), "recoverable backup verified")
}

func TestGatewayCORS_PersistenceDisabledWarnsButContinues(t *testing.T) {
	logger := logrus.New()
	var output strings.Builder
	logger.SetOutput(&output)
	client := newPersistenceProbeClient(false, false, true)
	logCORSValkeyPersistence(client, logger)
	require.Contains(t, output.String(), "DURABILITY WARNING")
	require.Equal(t, int64(1), client.pings.Load(), "the live Valkey connection remains usable")
}

func TestGatewayCORS_PersistenceEnabledValkeyIsAdvisoryAndNoBackupClaim(t *testing.T) {
	logger := logrus.New()
	var output strings.Builder
	logger.SetOutput(&output)
	client := newPersistenceProbeClient(true, false, false)
	logCORSValkeyPersistence(client, logger)
	require.Equal(t, int64(1), client.pings.Load())
	require.Contains(t, output.String(), "persistence is enabled")
	require.NotContains(t, output.String(), "backup verified")
	rdbClient := newPersistenceProbeClient(false, true, false)
	rdbLogger := logrus.New()
	var rdbOutput strings.Builder
	rdbLogger.SetOutput(&rdbOutput)
	logCORSValkeyPersistence(rdbClient, rdbLogger)
	require.Contains(t, rdbOutput.String(), "persistence is enabled")
	require.Equal(t, int64(1), rdbClient.pings.Load())
}

func TestGatewayCORS_PersistenceWarningAgainstReachableValkeyProtocol(t *testing.T) {
	t.Run("known disabled", func(t *testing.T) {
		addr := startPersistenceProtocolFixture(t, "")
		assertPersistenceStartupAndWarning(t, addr, true)
	})
	t.Run("enabled control", func(t *testing.T) {
		addr := startPersistenceProtocolFixture(t, "900 1")
		assertPersistenceStartupAndWarning(t, addr, false)
	})
}

func startPersistenceProtocolFixture(t *testing.T, save string) string {
	t.Helper()
	server, err := miniredisserver.NewServer("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(server.Close)
	require.NoError(t, server.Register("PING", func(peer *miniredisserver.Peer, _ string, _ []string) { peer.WriteInline("PONG") }))
	require.NoError(t, server.Register("INFO", func(peer *miniredisserver.Peer, _ string, args []string) {
		if len(args) == 1 && args[0] == "persistence" {
			peer.WriteBulk("# Persistence\r\naof_enabled:0\r\n")
			return
		}
		peer.WriteError("ERR unsupported INFO request")
	}))
	require.NoError(t, server.Register("CONFIG", func(peer *miniredisserver.Peer, _ string, args []string) {
		if len(args) == 2 && strings.EqualFold(args[0], "GET") && args[1] == "save" {
			peer.WriteLen(2)
			peer.WriteBulk("save")
			peer.WriteBulk(save)
			return
		}
		peer.WriteError("ERR unsupported CONFIG request")
	}))
	return server.Addr().String()
}

func boolPointer(value bool) *bool { return &value }

func assertPersistenceStartupAndWarning(t *testing.T, addr string, warning bool) {
	t.Helper()
	store, err := mpupkg.NewValkeyStateStoreWithLease(context.Background(), config.ValkeyConfig{
		Addr: addr, InsecureAllowPlaintext: true, EncryptState: boolPointer(false),
		DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
	}, nil, "", 0)
	require.NoError(t, err, "production Valkey state store startup must succeed against reachable Redis protocol")
	defer store.Close()
	client := store.Client()
	require.NoError(t, api.NewValkeyCORSStore(client).HealthCheck(context.Background()), "shared live Valkey remains usable")
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	var output strings.Builder
	logger.SetOutput(&output)
	logCORSValkeyPersistence(client, logger)
	if warning {
		require.Contains(t, output.String(), "DURABILITY WARNING")
		require.NotContains(t, output.String(), "persistence is enabled")
	} else {
		require.NotContains(t, output.String(), "DURABILITY WARNING")
		require.Contains(t, output.String(), "persistence is enabled")
	}
	require.NotContains(t, output.String(), "recoverable backup verified")
}

type persistenceProbeClient struct {
	redis.UniversalClient
	aofEnabled  bool
	rdbEnabled  bool
	unknown     bool
	pings       atomic.Int64
	infoCalls   atomic.Int64
	configCalls atomic.Int64
}

func newPersistenceProbeClient(aofEnabled, rdbEnabled, unknown bool) *persistenceProbeClient {
	return &persistenceProbeClient{aofEnabled: aofEnabled, rdbEnabled: rdbEnabled, unknown: unknown}
}

func (c *persistenceProbeClient) Ping(context.Context) *redis.StatusCmd {
	c.pings.Add(1)
	return redis.NewStatusResult("PONG", nil)
}

func (c *persistenceProbeClient) infoPersistence(ctx context.Context) *redis.StringCmd {
	return c.Info(ctx, "persistence")
}

func (c *persistenceProbeClient) configSave(ctx context.Context) *redis.MapStringStringCmd {
	return c.ConfigGet(ctx, "save")
}

func (c *persistenceProbeClient) Close() error       { return nil }
func (c *persistenceProbeClient) AddHook(redis.Hook) {}
func (c *persistenceProbeClient) Watch(context.Context, func(*redis.Tx) error, ...string) error {
	return nil
}
func (c *persistenceProbeClient) Do(context.Context, ...interface{}) *redis.Cmd {
	return redis.NewCmd(context.Background())
}
func (c *persistenceProbeClient) Process(context.Context, redis.Cmder) error { return nil }
func (c *persistenceProbeClient) AutoPipeline() (*redis.AutoPipeliner, error) {
	return nil, errors.New("unsupported in test fake")
}
func (c *persistenceProbeClient) AutoPipelineWithOptions(*redis.AutoPipelineOptions) (*redis.AutoPipeliner, error) {
	return nil, errors.New("unsupported in test fake")
}
func (c *persistenceProbeClient) AsyncAutoPipeline() (*redis.AutoPipeliner, error) {
	return nil, errors.New("unsupported in test fake")
}
func (c *persistenceProbeClient) AsyncAutoPipelineWithOptions(*redis.AutoPipelineOptions) (*redis.AutoPipeliner, error) {
	return nil, errors.New("unsupported in test fake")
}
func (c *persistenceProbeClient) Subscribe(context.Context, ...string) *redis.PubSub  { return nil }
func (c *persistenceProbeClient) PSubscribe(context.Context, ...string) *redis.PubSub { return nil }
func (c *persistenceProbeClient) SSubscribe(context.Context, ...string) *redis.PubSub { return nil }
func (c *persistenceProbeClient) PoolStats() *redis.PoolStats                         { return &redis.PoolStats{} }

func (c *persistenceProbeClient) Info(context.Context, ...string) *redis.StringCmd {
	c.infoCalls.Add(1)
	if c.unknown {
		return redis.NewStringResult("", nil)
	}
	if c.aofEnabled {
		return redis.NewStringResult("# Persistence\naof_enabled:1\n", nil)
	}
	return redis.NewStringResult("# Persistence\naof_enabled:0\n", nil)
}

func (c *persistenceProbeClient) ConfigGet(context.Context, string) *redis.MapStringStringCmd {
	c.configCalls.Add(1)
	save := ""
	if c.unknown {
		return redis.NewMapStringStringResult(map[string]string{}, nil)
	}
	if c.rdbEnabled {
		save = "900 1"
	}
	return redis.NewMapStringStringResult(map[string]string{"save": save}, nil)
}

func TestGatewayCORS_PersistenceStateParsing(t *testing.T) {
	aof, rdb, known := corsValkeyPersistenceState("aof_enabled:0\n", "900 1", nil, nil)
	require.True(t, known)
	require.False(t, aof)
	require.True(t, rdb)
	aof, rdb, known = corsValkeyPersistenceState("aof_enabled:1\n", "", nil, nil)
	require.True(t, known)
	require.True(t, aof)
	require.False(t, rdb)
	_, _, known = corsValkeyPersistenceState("", "", errors.New("unavailable"), nil)
	require.False(t, known)
}

func TestConfigApplier_SEC49ReconfiguresLiveManager(t *testing.T) {
	oldCfg := &config.Config{Server: config.ServerConfig{MaxAggregateSpoolBytes: 10}}
	newCfg := &config.Config{Server: config.ServerConfig{MaxAggregateSpoolBytes: 20}}
	manager := api.NewSpoolManager(10)
	m, ok := manager.(interface{ ReconfigureCapacity(int64) error })
	if !ok {
		t.Fatal("manager does not support reconfiguration")
	}
	a := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, oldCfg, nil, nil)
	a.SetSpoolManager(m)
	if err := a.ApplyConfigChanges(oldCfg, newCfg); err != nil {
		t.Fatal(err)
	}
	reservation, err := manager.Acquire(context.Background(), 20, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyConfigChanges(newCfg, &config.Config{Server: config.ServerConfig{MaxAggregateSpoolBytes: 10}}); err == nil {
		t.Fatal("expected shrink below reservation to fail")
	}
	reservation.Release()
}

func TestConfigApplier_SEC49ReloadsLiveVerifiedSpoolLimits(t *testing.T) {
	oldCfg := &config.Config{Server: config.ServerConfig{MaxVerifiedSpoolBytes: 64, MaxPartBuffer: 16, MaxAggregateSpoolBytes: 128}}
	newCfg := &config.Config{Server: config.ServerConfig{MaxVerifiedSpoolBytes: 256, MaxPartBuffer: 32, MaxAggregateSpoolBytes: 512}}
	source := api.NewSpoolLimitSource(api.SpoolLimitsForConfig(oldCfg))
	a := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, oldCfg, nil, nil)
	a.SetSpoolLimitSource(source)
	if err := a.ApplyConfigChanges(oldCfg, newCfg); err != nil {
		t.Fatal(err)
	}
	if got := source.Limits(); got != (api.SpoolLimits{Global: 256, Part: 32}) {
		t.Fatalf("live limits=%+v", got)
	}
}

func TestConfigApplier_SEC49InvalidOrShrinkVerifiedLimitIsSafe(t *testing.T) {
	source := api.NewSpoolLimitSource(api.SpoolLimits{Global: 100, Part: 20})
	source.Set(api.SpoolLimits{Global: 0, Part: 0})
	if got := source.Limits(); got != (api.SpoolLimits{Global: 100, Part: 20}) {
		t.Fatalf("invalid update changed live limits=%+v", got)
	}
	oldCfg := &config.Config{Server: config.ServerConfig{MaxVerifiedSpoolBytes: 100, MaxPartBuffer: 20}}
	newCfg := &config.Config{Server: config.ServerConfig{MaxVerifiedSpoolBytes: 10, MaxPartBuffer: 4}}
	a := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, oldCfg, nil, nil)
	a.SetSpoolLimitSource(source)
	if err := a.ApplyConfigChanges(oldCfg, newCfg); err != nil {
		t.Fatal(err)
	}
	if got := source.Limits(); got != (api.SpoolLimits{Global: 10, Part: 4}) {
		t.Fatalf("shrink limits=%+v", got)
	}
}

func TestInitTracing_InvalidExporter(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "invalid",
	}

	tp, err := InitTracing(cfg, logger)
	assert.Error(t, err)
	assert.Nil(t, tp)
	assert.Contains(t, err.Error(), "unsupported exporter")
}

func TestInitTracing_JaegerMissingEndpoint(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:        true,
		ServiceName:    "test-service",
		Exporter:       "jaeger",
		JaegerEndpoint: "", // Empty endpoint
	}

	tp, err := InitTracing(cfg, logger)
	// Jaeger exporter may succeed with empty endpoint, but should still return a valid provider
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
	require.NoError(t, err)
}

func TestInitTracing_OtlpMissingEndpoint(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:      true,
		ServiceName:  "test-service",
		Exporter:     "otlp",
		OtlpEndpoint: "", // Empty endpoint
	}

	tp, err := InitTracing(cfg, logger)
	// OTLP exporter may succeed with empty endpoint, but should still return a valid provider
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
	require.NoError(t, err)
}

func TestInitTracing_InvalidSamplingRatio(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:       true,
		ServiceName:   "test-service",
		Exporter:      "stdout",
		SamplingRatio: 2.0, // Invalid: > 1.0
	}

	tp, err := InitTracing(cfg, logger)
	require.NoError(t, err) // initTracing doesn't validate sampling ratio
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
}

func TestInitTracing_Disabled(t *testing.T) {
	// When tracing is disabled, initTracing should not be called
	// This test just verifies the config struct works when disabled
	cfg := config.TracingConfig{
		Enabled: false,
		// Other fields can be empty when disabled
	}

	// Just verify the struct is valid (no validation method on TracingConfig directly)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "", cfg.ServiceName)
}

func TestStringSlicesEqual(t *testing.T) {
	assert.True(t, stringSlicesEqual(nil, nil))
	assert.True(t, stringSlicesEqual([]string{}, []string{}))
	assert.True(t, stringSlicesEqual([]string{"a", "b"}, []string{"a", "b"}))
	assert.False(t, stringSlicesEqual([]string{"a"}, []string{"a", "b"}))
	assert.False(t, stringSlicesEqual([]string{"a", "b"}, []string{"a", "c"}))
	assert.False(t, stringSlicesEqual([]string{"a"}, nil))
}

func TestApplyConfigChanges_PolicyFiles(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	// Create temporary policy files
	tmpDir := t.TempDir()
	policyFile1 := tmpDir + "/policy1.yaml"
	policyFile2 := tmpDir + "/policy2.yaml"

	require.NoError(t, os.WriteFile(policyFile1, []byte(`
id: test-policy-1
buckets:
  - "test-*"
`), 0600))
	require.NoError(t, os.WriteFile(policyFile2, []byte(`
id: test-policy-2
buckets:
  - "other-*"
`), 0600))

	oldCfg := &config.Config{
		ListenAddr:  ":8080",
		PolicyFiles: []string{policyFile1},
	}
	newCfg := &config.Config{
		ListenAddr:  ":8080",
		PolicyFiles: []string{policyFile1, policyFile2},
	}

	pm := config.NewPolicyManager()
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, pm, nil)

	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.NotNil(t, applier.policyManager)
}

func TestApplyConfigChanges_CredentialAdditionBecomesActive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key2", SecretKey: "secret2"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)

	cred, err := store.Lookup("key2")
	require.NoError(t, err)
	assert.Equal(t, "key2", cred.AccessKey)
	assert.Equal(t, "secret2", cred.SecretKey)
}

func TestApplyConfigChanges_CredentialRemovalBecomesInactive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key2", SecretKey: "secret2"},
			},
		},
	}
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)

	_, err = store.Lookup("key2")
	assert.ErrorIs(t, err, api.ErrUnknownAccessKey)
}

func TestApplyConfigChanges_InvalidCredentialReloadRetainsOldCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}
	// Duplicate access key makes the config invalid for Replace.
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key1", SecretKey: "secret2"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace credential store")

	// Old credential should still be available after failed reload.
	cred, err := store.Lookup("key1")
	require.NoError(t, err)
	assert.Equal(t, "key1", cred.AccessKey)
	assert.Equal(t, "secret1", cred.SecretKey)
}

func TestApplyConfigChanges_RateLimitReconfiguration(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	newCfg := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: true,
			Limit:   100,
			Window:  time.Minute,
		},
	}

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, nil)
	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.NotNil(t, applier.RateLimiter)

	// Toggle off
	newCfg2 := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	err = applier.ApplyConfigChanges(newCfg, newCfg2)
	require.NoError(t, err)
	assert.Nil(t, applier.RateLimiter)
}

func TestApplyConfigChanges_LogLevelChange(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		LogLevel: "info",
	}
	newCfg := &config.Config{
		LogLevel: "debug",
	}

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, nil)
	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.Equal(t, logrus.DebugLevel, logger.Level)
}

// TestApplyConfigChanges_UnrelatedSectionsAreHandled exercises the
// restart-required branches (cache, audit, tracing, proxied bucket, server
// timeouts, logging) plus the invalid-log-level warning path so hot reloads
// involving credentials never mis-handle the surrounding configuration.
func TestApplyConfigChanges_UnrelatedSectionsAreHandled(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		LogLevel:      "info",
		Cache:         config.CacheConfig{Enabled: false},
		Audit:         config.AuditConfig{Enabled: false},
		Tracing:       config.TracingConfig{Enabled: false},
		ProxiedBucket: "old-bucket",
		Server:        config.ServerConfig{ReadTimeout: time.Second},
		Logging:       config.LoggingConfig{AccessLogFormat: "text"},
		Auth: config.AuthConfig{Credentials: []config.GatewayCredential{
			{AccessKey: "key", SecretKey: "secret"},
		}},
	}
	newCfg := &config.Config{
		LogLevel:      "not-a-valid-level",
		Cache:         config.CacheConfig{Enabled: true, MaxSize: 1024, MaxItems: 100, DefaultTTL: time.Minute},
		Audit:         config.AuditConfig{Enabled: true, MaxEvents: 10},
		Tracing:       config.TracingConfig{Enabled: true, ServiceName: "svc"},
		ProxiedBucket: "new-bucket",
		Server:        config.ServerConfig{ReadTimeout: 2 * time.Second},
		Logging:       config.LoggingConfig{AccessLogFormat: "json"},
		Auth: config.AuthConfig{Credentials: []config.GatewayCredential{
			{AccessKey: "key", SecretKey: "secret"},
		}},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	require.NoError(t, applier.ApplyConfigChanges(oldCfg, newCfg))

	// The credential store must still serve the credential after the reload.
	cred, err := store.Lookup("key")
	require.NoError(t, err)
	assert.Equal(t, "secret", cred.SecretKey)
}

// --- End-to-end hot-reload coverage: real file events / SIGHUP trigger
// LoadConfig, the reload callback drives ConfigChangeApplier, and the live
// credential store reflects the complete new snapshot. ---

// reloadCredential describes one auth credential entry in a test config file.
type reloadCredential struct {
	accessKey         string
	secretKey         string
	buckets           string // YAML fragment; empty omits the field
	bucketPermissions string // YAML fragment; empty omits the field
}

func writeReloadConfig(t *testing.T, path string, creds ...reloadCredential) {
	t.Helper()
	var credsYAML strings.Builder
	for _, c := range creds {
		fmt.Fprintf(&credsYAML, "    - access_key: %q\n      secret_key: %q\n", c.accessKey, c.secretKey)
		if c.buckets != "" {
			fmt.Fprintf(&credsYAML, "      buckets: %s\n", c.buckets)
		}
		if c.bucketPermissions != "" {
			fmt.Fprintf(&credsYAML, "      bucket_permissions: %s\n", c.bucketPermissions)
		}
	}
	yaml := fmt.Sprintf(`log_level: info
listen_addr: ":8080"
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
%s`, credsYAML.String())
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// newReloadHarness wires a real ConfigReloader to a real ConfigChangeApplier
// and a live credential store, mirroring the production wiring in run().
func newReloadHarness(t *testing.T, configPath string, cfg *config.Config) (*api.StaticCredentialStore, *config.ConfigReloader) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	store, err := api.NewStaticCredentialStore(cfg.Auth.Credentials)
	require.NoError(t, err)
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, cfg, nil, store)
	reloader, err := config.NewConfigReloader(configPath, cfg, logger)
	require.NoError(t, err)
	reloader.SetOnReloadCallback(applier.ApplyConfigChanges)
	go reloader.Start()
	t.Cleanup(reloader.Stop)
	return store, reloader
}

func waitForCondition(t *testing.T, timeout time.Duration, description string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestConfigReloader_CredentialAdditionBecomesActive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond) // allow the directory watcher to start
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "key2", secretKey: "secret2", buckets: `["tenant-a", "shared-*"]`})

	waitForCondition(t, 5*time.Second, "key2 becoming active", func() bool {
		cred, err := store.Lookup("key2")
		return err == nil && cred.SecretKey == "secret2" &&
			cred.AllowsBucket("tenant-a") && cred.AllowsBucket("shared-x") && !cred.AllowsBucket("other")
	})
}

func TestConfigChangeApplier_ReloadsMPULegacyRoutingGate(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	writeMPUReloadConfig := func(enabled bool) {
		value := "false"
		if enabled {
			value = "true"
		}
		require.NoError(t, os.WriteFile(configPath, []byte("log_level: info\nbackend:\n  access_key: backend\n  secret_key: secret\nencryption:\n  password: password\nauth:\n  credentials:\n    - access_key: gateway\n      secret_key: gateway-secret\nmultipart_state:\n  allow_untracked_plaintext_uploads: "+value+"\n"), 0o644))
	}
	writeMPUReloadConfig(false)
	oldCfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	gate := &reloadMPURoutingGate{}
	applier := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, oldCfg, nil, nil)
	applier.SetMPURoutingGate(gate)
	reloader, err := config.NewConfigReloader(configPath, oldCfg, logrus.New())
	require.NoError(t, err)
	reloader.SetOnReloadCallback(applier.ApplyConfigChanges)
	go reloader.Start()
	t.Cleanup(reloader.Stop)
	time.Sleep(100 * time.Millisecond)

	writeMPUReloadConfig(true)
	waitForCondition(t, 5*time.Second, "legacy MPU routing gate enabling", func() bool { return gate.enabled.Load() })
	writeMPUReloadConfig(false)
	waitForCondition(t, 5*time.Second, "legacy MPU routing gate disabling", func() bool { return !gate.enabled.Load() })
}

type reloadMPURoutingGate struct{ enabled atomic.Bool }

func (g *reloadMPURoutingGate) SetAllowUntrackedPlaintextUploads(enabled bool) {
	g.enabled.Store(enabled)
}

func TestConfigReloader_CredentialRemovalBecomesInactive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "key2", secretKey: "secret2"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	waitForCondition(t, 5*time.Second, "key2 becoming inactive", func() bool {
		_, err := store.Lookup("key2")
		return errors.Is(err, api.ErrUnknownAccessKey)
	})
	if _, err := store.Lookup("key1"); err != nil {
		t.Fatalf("key1 must remain active: %v", err)
	}
}

func TestConfigReloader_EndToEnd_ScopeChangeBecomesActive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1", buckets: `["tenant-a"]`})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1", buckets: `["tenant-b"]`})

	waitForCondition(t, 5*time.Second, "key1 scope change", func() bool {
		cred, err := store.Lookup("key1")
		return err == nil && cred.AllowsBucket("tenant-b") && !cred.AllowsBucket("tenant-a")
	})
}

func TestConfigReloader_EndToEnd_BucketManagePermissionChange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	cred, err := store.Lookup("key1")
	require.NoError(t, err)
	assert.False(t, cred.HasBucketPermission(config.BucketPermissionManage))

	time.Sleep(100 * time.Millisecond)
	writeReloadConfig(t, configPath, reloadCredential{
		accessKey:         "key1",
		secretKey:         "secret1",
		bucketPermissions: "[manage]",
	})

	waitForCondition(t, 5*time.Second, "key1 manage permission activation", func() bool {
		cred, err := store.Lookup("key1")
		return err == nil && cred.HasBucketPermission(config.BucketPermissionManage)
	})

	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})
	waitForCondition(t, 5*time.Second, "key1 manage permission revocation", func() bool {
		cred, err := store.Lookup("key1")
		return err == nil && !cred.HasBucketPermission(config.BucketPermissionManage)
	})
}

func TestConfigReloader_InvalidCredentialReloadRetainsOldCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, reloader := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	// Duplicate access keys make the reloaded config invalid; the reload
	// must be rejected wholesale and the live store unchanged.
	var invalidYAML strings.Builder
	fmt.Fprintf(&invalidYAML, "    - access_key: %q\n      secret_key: %q\n", "key1", "secret-x")
	fmt.Fprintf(&invalidYAML, "    - access_key: %q\n      secret_key: %q\n", "key1", "secret-y")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})
	invalid := fmt.Sprintf(`log_level: info
listen_addr: ":8080"
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
%s`, invalidYAML.String())
	require.NoError(t, os.WriteFile(configPath, []byte(invalid), 0o644))

	// Give the watcher time to observe and reject the invalid config, then
	// assert the old snapshot is untouched.
	time.Sleep(400 * time.Millisecond)
	cred, err := store.Lookup("key1")
	require.NoError(t, err)
	assert.Equal(t, "secret1", cred.SecretKey)
	if _, err := store.Lookup("key2"); !errors.Is(err, api.ErrUnknownAccessKey) {
		t.Fatalf("invalid reload must not publish partial state")
	}
	current := reloader.GetCurrentConfig()
	require.Len(t, current.Auth.Credentials, 1)
	assert.Equal(t, "key1", current.Auth.Credentials[0].AccessKey)
}

func TestConfigReloader_EndToEnd_CredentialsFileReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	credPath := filepath.Join(tmpDir, "credentials.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})
	require.NoError(t, os.WriteFile(credPath, []byte("- access_key: \"file-key\"\n  secret_key: \"file-secret-v1\"\n"), 0o644))
	t.Setenv("AUTH_CREDENTIALS_FILE", credPath)

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)

	// Atomic replacement via rename — the watcher must follow it.
	newCredPath := filepath.Join(tmpDir, "credentials-new.yaml")
	require.NoError(t, os.WriteFile(newCredPath, []byte("- access_key: \"file-key\"\n  secret_key: \"file-secret-v2\"\n  buckets: [\"file-bucket\"]\n"), 0o644))
	require.NoError(t, os.Rename(newCredPath, credPath))

	waitForCondition(t, 5*time.Second, "credentials-file rename reload", func() bool {
		cred, err := store.Lookup("file-key")
		return err == nil && cred.SecretKey == "file-secret-v2" && cred.AllowsBucket("file-bucket")
	})
}

func TestConfigReloader_EndToEnd_SIGHUPReloadsCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	// Write the new state before starting the watcher. The test's only
	// triggering event is SIGHUP, not a file notification.
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "sighup-key", secretKey: "sighup-secret"})
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	// Exercise the signal path end-to-end (LoadConfig -> callback -> live store).
	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, process.Signal(syscall.SIGHUP))

	waitForCondition(t, 5*time.Second, "SIGHUP credential reload", func() bool {
		cred, err := store.Lookup("sighup-key")
		return err == nil && cred.SecretKey == "sighup-secret"
	})
	if _, err := store.Lookup("key1"); err != nil {
		t.Fatalf("key1 must remain active after SIGHUP reload: %v", err)
	}
}
