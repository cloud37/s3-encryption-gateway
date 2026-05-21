package main

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
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
		ListenAddr: ":8080",
		PolicyFiles: []string{policyFile1},
	}
	newCfg := &config.Config{
		ListenAddr: ":8080",
		PolicyFiles: []string{policyFile1, policyFile2},
	}

	pm := config.NewPolicyManager()
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, pm)

	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.NotNil(t, applier.policyManager)
}
