// Package provider — Valkey fixture.
//
// Unlike MinIO / Garage / RustFS, Valkey is not an S3 backend and therefore
// does not implement the full Provider interface. Instead it exposes a
// StartValkey helper that returns a ValkeyInstance for encrypted-MPU tests
// that need a real Valkey state store.
package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	tc "github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// ValkeyInstance holds the connection details for a running Valkey container.
type ValkeyInstance struct {
	// Addr is host:port, e.g. "127.0.0.1:6379".
	Addr string
	// Password is empty for the default no-auth configuration.
	Password  string
	container tc.Container
}

// Stop makes the Valkey endpoint unavailable without removing the fixture.
func (v ValkeyInstance) Stop(ctx context.Context) error {
	if v.container == nil {
		return nil
	}
	return v.container.Stop(ctx, nil)
}

// StartValkey starts an ephemeral Valkey container via Testcontainers and
// registers t.Cleanup to terminate it. Returns ValkeyInstance with the
// mapped address. The test is skipped if Docker is unavailable.
func StartValkey(ctx context.Context, t *testing.T) ValkeyInstance {
	t.Helper()

	if os.Getenv("GATEWAY_TEST_SKIP_VALKEY") != "" {
		t.Skip("Valkey fixture skipped (GATEWAY_TEST_SKIP_VALKEY is set)")
	}

	// Re-use the Redis module — Valkey is wire-compatible.
	c, err := tcredis.Run(ctx, "valkey/valkey:8.0-alpine")
	if err != nil {
		t.Skipf("valkey fixture: failed to start container (Docker unavailable?): %v", err)
		return ValkeyInstance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("valkey fixture: host: %v", err)
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("valkey fixture: port: %v", err)
	}

	return ValkeyInstance{
		Addr:      fmt.Sprintf("%s:%s", host, port.Port()),
		container: c,
	}
}
