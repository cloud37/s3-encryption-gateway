package config

import (
	"strings"
	"testing"
)

func TestConfigValidate_SpoolLimits(t *testing.T) {
	cases := []struct {
		name              string
		single, aggregate int64
		want              string
	}{
		{"positive", 1, 2, ""},
		{"single required", 0, 2, "max_verified_spool_bytes"},
		{"negative single rejected", -1, 2, "max_verified_spool_bytes"},
		{"aggregate must cover single", 2, 1, "max_aggregate_spool_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfigForTest()
			c.Server.MaxVerifiedSpoolBytes = tc.single
			c.Server.MaxAggregateSpoolBytes = tc.aggregate
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestConfigValidate_ZeroValueSpoolCompatibility(t *testing.T) {
	c := DefaultConfigForTest()
	c.Server.MaxVerifiedSpoolBytes = 0
	c.Server.MaxAggregateSpoolBytes = 0
	if err := c.Validate(); err != nil && strings.Contains(err.Error(), "spool") {
		t.Fatalf("unexpected spool validation error: %v", err)
	}
}

func DefaultConfigForTest() *Config {
	c := &Config{ListenAddr: ":8080", Encryption: EncryptionConfig{Password: "test-password", KDF: KDFConfig{PBKDF2: PBKDF2Config{Iterations: 600000}}}}
	c.Auth.Credentials = []GatewayCredential{{AccessKey: "a", SecretKey: "b"}}
	c.Backend = BackendConfig{Endpoint: "https://localhost:9000", AccessKey: "a", SecretKey: "b", TLS: BackendTLSConfig{InsecureSkipVerify: true}}
	return c
}
