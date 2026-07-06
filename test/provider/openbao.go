// Package provider — OpenBao / Vault Transit KMS fixture.
//
// Unlike S3 backends, OpenBao is not an S3 provider and therefore does not
// implement the full Provider interface. Instead it exposes a StartOpenBao
// helper that starts an OpenBao dev-server container, enables the Transit
// secrets engine, creates a non-exportable AES-256-GCM-96 wrapping key, and
// optionally provisions an AppRole with a short token TTL for renewal tests.
// It returns an OpenBaoInstance for conformance tests that exercise
// CapOpenBaoKMS.
package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	bao "github.com/openbao/openbao/api/v2"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// openBaoImage is the official OpenBao container image.
	openBaoImage = "quay.io/openbao/openbao:2.5.5"

	// openBaoPort is the HTTP port the dev server listens on.
	openBaoPort = "8200/tcp"

	// openBaoRootToken is the fixed root token used in dev mode.
	openBaoRootToken = "root"

	// openBaoTransitMount is the Transit secrets engine mount path.
	openBaoTransitMount = "transit"

	// OpenBaoKeyName is the Transit key name pre-created by the fixture.
	OpenBaoKeyName = "s3gw-dek"
)

// OpenBaoInstance holds the connection details for a running OpenBao container.
type OpenBaoInstance struct {
	// Address is the base HTTP URL, e.g. "http://127.0.0.1:8200".
	Address string
	// RootToken is the root token for the dev server.
	RootToken string
	// KeyName is the Transit key pre-created by the fixture.
	KeyName string
	// TransitMount is the mount path of the Transit secrets engine.
	TransitMount string
	// AppRoleID and AppRoleSecret are populated when WithOpenBaoAppRole is
	// passed as an option to StartOpenBao.
	AppRoleID     string
	AppRoleSecret string
}

// openBaoOptions controls optional behaviour of StartOpenBao.
type openBaoOptions struct {
	withAppRole bool
	tokenTTL    time.Duration
}

// OpenBaoOption is a functional option for StartOpenBao.
type OpenBaoOption func(*openBaoOptions)

// WithOpenBaoAppRole provisions an AppRole (role "s3gw") with the given token
// TTL. The returned OpenBaoInstance will have AppRoleID and AppRoleSecret set.
// A short TTL (e.g. 5s) is useful for testing the in-process renewal goroutine.
func WithOpenBaoAppRole(tokenTTL time.Duration) OpenBaoOption {
	return func(o *openBaoOptions) {
		o.withAppRole = true
		o.tokenTTL = tokenTTL
	}
}

// StartOpenBao starts an ephemeral OpenBao dev-server container via
// Testcontainers, enables the Transit secrets engine, creates a non-exportable
// AES-256-GCM-96 wrapping key, and returns an OpenBaoInstance.
// t.Cleanup is registered internally; callers do not manage teardown.
// The test is skipped if Docker is unavailable or GATEWAY_TEST_SKIP_OPENBAO is
// set.
func StartOpenBao(ctx context.Context, t *testing.T, opts ...OpenBaoOption) OpenBaoInstance {
	t.Helper()

	if os.Getenv("GATEWAY_TEST_SKIP_OPENBAO") != "" {
		t.Skip("OpenBao fixture skipped (GATEWAY_TEST_SKIP_OPENBAO is set)")
		return OpenBaoInstance{}
	}

	cfg := &openBaoOptions{tokenTTL: 5 * time.Second}
	for _, o := range opts {
		o(cfg)
	}

	req := tc.ContainerRequest{
		Image:        openBaoImage,
		ExposedPorts: []string{openBaoPort},
		Env: map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID": openBaoRootToken,
		},
		Cmd: []string{"server", "-dev", "-dev-listen-address=0.0.0.0:8200"},
		WaitingFor: wait.ForHTTP("/v1/sys/health").
			WithPort(openBaoPort).
			WithStatusCodeMatcher(func(s int) bool { return s == 200 || s == 429 }).
			WithStartupTimeout(60 * time.Second).
			WithPollInterval(500 * time.Millisecond),
	}

	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("openbao fixture: failed to start container (Docker unavailable?): %v", err)
		return OpenBaoInstance{}
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("openbao fixture: host: %v", err)
	}
	port, err := container.MappedPort(ctx, openBaoPort)
	if err != nil {
		t.Fatalf("openbao fixture: port: %v", err)
	}

	addr := fmt.Sprintf("http://%s:%s", host, port.Port())

	if err := openBaoSetupTransit(ctx, t, addr); err != nil {
		t.Fatalf("openbao fixture: transit setup: %v", err)
	}

	inst := OpenBaoInstance{
		Address:      addr,
		RootToken:    openBaoRootToken,
		KeyName:      OpenBaoKeyName,
		TransitMount: openBaoTransitMount,
	}

	if cfg.withAppRole {
		roleID, secretID, err := openBaoSetupAppRole(ctx, t, addr, cfg.tokenTTL)
		if err != nil {
			t.Fatalf("openbao fixture: approle setup: %v", err)
		}
		inst.AppRoleID = roleID
		inst.AppRoleSecret = secretID
	}

	return inst
}

// openBaoSetupTransit enables the Transit engine and creates the wrapping key.
func openBaoSetupTransit(ctx context.Context, t *testing.T, addr string) error {
	t.Helper()
	client, err := openBaoAdminClient(addr)
	if err != nil {
		return err
	}
	l := client.Logical()

	if _, err := l.WriteWithContext(ctx, "sys/mounts/"+openBaoTransitMount,
		map[string]any{"type": "transit"}); err != nil {
		return fmt.Errorf("enable transit: %w", err)
	}
	if _, err := l.WriteWithContext(ctx, openBaoTransitMount+"/keys/"+OpenBaoKeyName,
		map[string]any{"type": "aes256-gcm96"}); err != nil {
		return fmt.Errorf("create transit key: %w", err)
	}
	return nil
}

// openBaoSetupAppRole enables AppRole auth, writes a tightly-scoped policy,
// and returns a fresh role_id / secret_id pair.
func openBaoSetupAppRole(ctx context.Context, t *testing.T, addr string, ttl time.Duration) (roleID, secretID string, err error) {
	t.Helper()
	client, err := openBaoAdminClient(addr)
	if err != nil {
		return "", "", err
	}
	l := client.Logical()

	if _, err := l.WriteWithContext(ctx, "sys/auth/approle",
		map[string]any{"type": "approle"}); err != nil {
		return "", "", fmt.Errorf("enable approle: %w", err)
	}

	// Minimal policy: encrypt, decrypt, read key (for HealthCheck), rotate.
	// Deliberately omits "create" so a missing key_name is a hard error.
	policy := fmt.Sprintf(`
path "%[1]s/encrypt/%[2]s"      { capabilities = ["update"] }
path "%[1]s/decrypt/%[2]s"      { capabilities = ["update"] }
path "%[1]s/keys/%[2]s"         { capabilities = ["read"] }
path "%[1]s/keys/%[2]s/rotate"  { capabilities = ["update"] }
`, openBaoTransitMount, OpenBaoKeyName)

	if _, err := l.WriteWithContext(ctx, "sys/policies/acl/s3gw",
		map[string]any{"policy": policy}); err != nil {
		return "", "", fmt.Errorf("write policy: %w", err)
	}

	ttlStr := ttl.String()
	if _, err := l.WriteWithContext(ctx, "auth/approle/role/s3gw", map[string]any{
		"token_policies": "s3gw",
		"token_ttl":      ttlStr,
		"period":         ttlStr, // periodic → renewable indefinitely past max_ttl
	}); err != nil {
		return "", "", fmt.Errorf("create approle role: %w", err)
	}

	rid, err := l.ReadWithContext(ctx, "auth/approle/role/s3gw/role-id")
	if err != nil {
		return "", "", fmt.Errorf("read role-id: %w", err)
	}
	roleID, _ = rid.Data["role_id"].(string)

	sid, err := l.WriteWithContext(ctx, "auth/approle/role/s3gw/secret-id", nil)
	if err != nil {
		return "", "", fmt.Errorf("generate secret-id: %w", err)
	}
	secretID, _ = sid.Data["secret_id"].(string)

	return roleID, secretID, nil
}

// openBaoAdminClient returns a *bao.Client authenticated with the root token.
func openBaoAdminClient(addr string) (*bao.Client, error) {
	cfg := bao.DefaultConfig()
	cfg.Address = addr
	client, err := bao.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("bao client: %w", err)
	}
	client.SetToken(openBaoRootToken)
	return client, nil
}
