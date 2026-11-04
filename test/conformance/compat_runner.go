package conformance

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	container "github.com/moby/moby/api/types/container"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// sdkToolRunner is the common interface for launching an external SDK/CLI
// tool inside a Docker container against the gateway.
type sdkToolRunner interface {
	// Name returns the tool name for log output (e.g. "boto3", "awscli").
	Name() string
	// Image returns the Docker image tag to pull (e.g. "amazon/aws-cli:2.22.0").
	// Return "" for in-process runners (no container required).
	Image() string
	// Script returns the inline shell/Python script or command args to execute.
	// The caller injects gateway endpoint, credentials, and bucket as
	// environment variables before running the container.
	Script(env sdkTestEnv) string
	// AssertOutput inspects the container exit code and stdout/stderr.
	// Returns nil on success, a descriptive error on failure.
	AssertOutput(exitCode int, stdout, stderr string) error
}

// sdkTestEnv carries the gateway endpoint and credentials for injection into
// the container environment.
type sdkTestEnv struct {
	Endpoint             string // e.g. "http://127.0.0.1:8080" (gateway, not backend)
	Region               string
	AccessKey            string
	SecretKey            string
	SessionToken         string // optional gateway session token; injected only when non-empty
	Bucket               string
	Key                  string // unique object key for this test run
	BrowserPageURL       string // ephemeral loopback page origin for Chromium CORS tests
	BrowserDeniedPageURL string // a distinct loopback origin excluded by gateway CORS
	BrowserStageURL      string // ephemeral loopback control endpoint for safe browser stage markers
	// BackendEndpoint is the *direct* S3 backend URL (bypassing the gateway).
	// Empty by default. Runners that exercise a hybrid gateway→backend path
	// (e.g. backup via gateway, restore directly from S3) populate this and
	// runToolContainer injects it as BACKEND_ENDPOINT into the container env.
	BackendEndpoint string
}

type safeSDKOutputRunner interface {
	suppressSDKOutput() bool
}

type sdkModeRunner interface{ testMode() string }

type sdkSessionTokenRunner interface{ requiresSessionToken() bool }

type sdkRunnerTimeout interface {
	containerTimeout() time.Duration
}

func sdkContainerEnvironment(env sdkTestEnv, runner sdkToolRunner) map[string]string {
	out := map[string]string{
		"AWS_ACCESS_KEY_ID":     env.AccessKey,
		"AWS_SECRET_ACCESS_KEY": env.SecretKey,
		"AWS_DEFAULT_REGION":    env.Region,
		"GATEWAY_ENDPOINT":      env.Endpoint,
		"GATEWAY_BUCKET":        env.Bucket,
		"GATEWAY_KEY":           env.Key,
	}
	if env.SessionToken != "" {
		out["AWS_SESSION_TOKEN"] = env.SessionToken
	}
	if env.BackendEndpoint != "" {
		out["BACKEND_ENDPOINT"] = env.BackendEndpoint
	}
	if env.BrowserPageURL != "" {
		out["BROWSER_PAGE_URL"] = env.BrowserPageURL
	}
	if env.BrowserDeniedPageURL != "" {
		out["BROWSER_DENIED_PAGE_URL"] = env.BrowserDeniedPageURL
	}
	if env.BrowserStageURL != "" {
		out["BROWSER_STAGE_URL"] = env.BrowserStageURL
	}
	if mode, ok := runner.(sdkModeRunner); ok && mode.testMode() != "" {
		out["GH353_SESSION_MODE"] = mode.testMode()
	}
	if needs, ok := runner.(sdkSessionTokenRunner); ok && needs.requiresSessionToken() && env.SessionToken == "" {
		delete(out, "AWS_SESSION_TOKEN")
		out["GH353_SESSION_MODE"] = "session"
	}
	return out
}

// runToolContainer launches a Docker container running the given SDK/CLI tool
// and asserts its output. It injects the test environment as environment
// variables and captures stdout/stderr for diagnostics.
//
// GAP-COMPAT1-4 — Network mode: containers use --network=host so they share
// the host's network namespace. This means 127.0.0.1 inside the container
// reaches the host's loopback directly, and no Docker bridge IP resolution
// is needed. This approach is portable across Linux Docker variants
// (rootless, native). macOS/Windows Docker Desktop does not support host
// networking; those platforms should use testcontainers' port mapping or
// host.docker.internal instead.
func runToolContainer(ctx context.Context, t *testing.T, runner sdkToolRunner, env sdkTestEnv) error {
	t.Helper()

	image := runner.Image()
	if image == "" {
		return fmt.Errorf("runToolContainer: %s has no image (in-process runner should not call this)", runner.Name())
	}

	script := runner.Script(env)

	req := tc.ContainerRequest{
		Image:      image,
		Entrypoint: []string{},
		Cmd:        []string{"/bin/sh", "-c", script},
		Env:        sdkContainerEnvironment(env, runner),
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.NetworkMode = container.NetworkMode("host")
		},
		WaitingFor: wait.ForExit().WithExitTimeout(runnerContainerTimeout(runner)),
	}

	safeOutput := false
	if safe, ok := runner.(safeSDKOutputRunner); ok {
		safeOutput = safe.suppressSDKOutput()
	}

	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		if safeOutput {
			return fmt.Errorf("%s: container execution failed", runner.Name())
		}
		return fmt.Errorf("%s: start container: %w", runner.Name(), err)
	}
	defer func() {
		_ = c.Terminate(context.Background())
	}()

	logReader, err := c.Logs(ctx)
	if err != nil {
		if safeOutput {
			return fmt.Errorf("%s: container execution failed", runner.Name())
		}
		return fmt.Errorf("%s: read logs: %w", runner.Name(), err)
	}
	defer logReader.Close()
	stdoutBytes, err := io.ReadAll(logReader)
	if err != nil {
		if safeOutput {
			return fmt.Errorf("%s: container execution failed", runner.Name())
		}
		return fmt.Errorf("%s: read stdout: %w", runner.Name(), err)
	}
	stdoutStr := string(stdoutBytes)
	if safeOutput {
		// Keep captured output private to AssertOutput; diagnostics/logs never include it.
		defer func() {
			clear(stdoutBytes)
			stdoutStr = ""
		}()
	}

	var stderrStr string

	exitCode, err := c.State(ctx)
	if err != nil {
		if safeOutput {
			return fmt.Errorf("%s: container execution failed", runner.Name())
		}
		return fmt.Errorf("%s: state: %w", runner.Name(), err)
	}

	if safeOutput {
		t.Logf("%s: container exit code %d; SDK output suppressed", runner.Name(), exitCode.ExitCode)
	} else {
		t.Logf("%s: exit code %d, stdout:\\n%s", runner.Name(), exitCode.ExitCode, stdoutStr)
		if stderrStr != "" {
			t.Logf("%s: stderr:\\n%s", runner.Name(), stderrStr)
		}
	}

	return runner.AssertOutput(exitCode.ExitCode, stdoutStr, stderrStr)
}

func runnerContainerTimeout(runner sdkToolRunner) time.Duration {
	if configured, ok := runner.(sdkRunnerTimeout); ok {
		return configured.containerTimeout()
	}
	return 120 * time.Second
}

var compatKeySeq int64

// compatUniqueKey returns a unique object key for compat tests.
func compatUniqueKey(t *testing.T) string {
	t.Helper()
	n := atomic.AddInt64(&compatKeySeq, 1)
	return fmt.Sprintf("compat/%s/%d-%d", t.Name(), n, time.Now().UnixNano())
}

// newUniqueTestEnv creates an sdkTestEnv for a single compat test run.
// The gateway is started with harness.StartGateway, and a unique key is
// generated to avoid collisions between parallel test runs.
func newUniqueTestEnv(t *testing.T, inst provider.Instance) (*harness.Gateway, sdkTestEnv) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	return gw, sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       compatUniqueKey(t),
	}
}
