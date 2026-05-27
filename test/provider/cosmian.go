// Package provider — Cosmian KMS fixture.
//
// Unlike S3 backends, Cosmian KMS is not an S3 provider and therefore does not
// implement the full Provider interface. Instead it exposes a StartCosmianKMS
// helper that starts the KMS container, creates a wrapping key, and returns a
// CosmianKMSInstance for conformance tests that exercise CapKMSIntegration.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// cosmianKMSImage is the official Cosmian KMS container image.
	cosmianKMSImage = "ghcr.io/cosmian/kms:5.22.0"

	// cosmianKMSPort is the default HTTP port the KMS listens on.
	cosmianKMSPort = "9998/tcp"

	// cosmianKMSReadyPath is the endpoint polled to detect readiness.
	cosmianKMSReadyPath = "/version"

	// cosmianKMIPPath is the KMIP 2.1 JSON API path.
	cosmianKMIPPath = "/kmip/2_1"
)

// CosmianKMSInstance holds the connection details for a running Cosmian KMS container.
type CosmianKMSInstance struct {
	// Endpoint is the base HTTP URL, e.g. "http://127.0.0.1:9998".
	Endpoint string
	// KeyID is the unique identifier of the pre-created AES-256 wrapping key.
	KeyID string
}

// StartCosmianKMS starts an ephemeral Cosmian KMS container via Testcontainers,
// creates a 256-bit AES wrapping key, and returns a CosmianKMSInstance.
// t.Cleanup is registered internally; callers do not manage teardown.
// The test is skipped if Docker is unavailable or GATEWAY_TEST_SKIP_COSMIAN is set.
func StartCosmianKMS(ctx context.Context, t *testing.T) CosmianKMSInstance {
	t.Helper()

	if os.Getenv("GATEWAY_TEST_SKIP_COSMIAN") != "" {
		t.Skip("Cosmian KMS fixture skipped (GATEWAY_TEST_SKIP_COSMIAN is set)")
		return CosmianKMSInstance{}
	}

	req := tc.ContainerRequest{
		Image:        cosmianKMSImage,
		ExposedPorts: []string{cosmianKMSPort},
		WaitingFor: wait.ForHTTP(cosmianKMSReadyPath).
			WithPort(cosmianKMSPort).
			WithStartupTimeout(60 * time.Second).
			WithPollInterval(500 * time.Millisecond),
	}

	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("cosmian KMS fixture: failed to start container (Docker unavailable?): %v", err)
		return CosmianKMSInstance{}
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("cosmian KMS fixture: host: %v", err)
	}
	port, err := container.MappedPort(ctx, cosmianKMSPort)
	if err != nil {
		t.Fatalf("cosmian KMS fixture: port: %v", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	// Create a 256-bit AES wrapping key.
	keyID, err := cosmianCreateAESKey(ctx, endpoint)
	if err != nil {
		t.Fatalf("cosmian KMS fixture: create wrapping key: %v", err)
	}

	return CosmianKMSInstance{
		Endpoint: endpoint,
		KeyID:    keyID,
	}
}

// cosmianCreateAESKey creates a 256-bit AES symmetric key in the KMS,
// activates it (Cosmian KMS keys are created in PreActive state and must be
// activated before they can be used for Encrypt/Decrypt), and returns its
// unique identifier. Uses the KMIP 2.1 JSON API.
func cosmianCreateAESKey(ctx context.Context, endpoint string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	// Step 1: Create the key.
	createReq := map[string]interface{}{
		"tag": "Create",
		"value": []interface{}{
			map[string]interface{}{
				"tag":   "ObjectType",
				"type":  "Enumeration",
				"value": "SymmetricKey",
			},
			map[string]interface{}{
				"tag": "Attributes",
				"value": []interface{}{
					map[string]interface{}{
						"tag":   "CryptographicAlgorithm",
						"type":  "Enumeration",
						"value": "AES",
					},
					map[string]interface{}{
						"tag":   "CryptographicLength",
						"type":  "Integer",
						"value": 256,
					},
					map[string]interface{}{
						"tag":  "CryptographicUsageMask",
						"type": "Integer",
						// Encrypt (4) | Decrypt (8) | WrapKey (2048) | UnwrapKey (4096)
						"value": 4 | 8 | 2048 | 4096,
					},
				},
			},
		},
	}

	createResp, err := cosmianKMIPPost(ctx, client, endpoint, createReq)
	if err != nil {
		return "", fmt.Errorf("Create: %w", err)
	}

	keyID, err := cosmianExtractUniqueIdentifier(createResp)
	if err != nil {
		return "", fmt.Errorf("Create: %w", err)
	}

	// Step 2: Activate the key.
	// Cosmian KMS creates keys in PreActive state. The key must be transitioned
	// to Active via the KMIP Activate operation before Encrypt/Decrypt are
	// permitted.
	activateReq := map[string]interface{}{
		"tag": "Activate",
		"value": []interface{}{
			map[string]interface{}{
				"tag":   "UniqueIdentifier",
				"type":  "TextString",
				"value": keyID,
			},
		},
	}

	if _, err := cosmianKMIPPost(ctx, client, endpoint, activateReq); err != nil {
		return "", fmt.Errorf("Activate key %s: %w", keyID, err)
	}

	return keyID, nil
}

// cosmianKMIPPost sends a single KMIP 2.1 JSON request to the KMS and returns
// the raw response body.
func cosmianKMIPPost(ctx context.Context, client *http.Client, endpoint string, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+cosmianKMIPPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("KMS HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// cosmianExtractUniqueIdentifier extracts the UniqueIdentifier value from a
// KMIP 2.1 JSON Create response.
func cosmianExtractUniqueIdentifier(data []byte) (string, error) {
	// The response is an array of KMIP nodes:
	// [{"tag":"UniqueIdentifier","type":"TextString","value":"<uuid>"}]
	// OR a single object wrapping a value array.
	// Try both shapes.

	// Shape 1: top-level object with "value" array.
	var obj struct {
		Tag   string            `json:"tag"`
		Value json.RawMessage   `json:"value"`
	}
	if err := json.Unmarshal(data, &obj); err == nil && obj.Tag != "" {
		// Try to parse "value" as an array of nodes.
		var children []struct {
			Tag   string `json:"tag"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if err2 := json.Unmarshal(obj.Value, &children); err2 == nil {
			for _, c := range children {
				if strings.EqualFold(c.Tag, "UniqueIdentifier") {
					return c.Value, nil
				}
			}
		}
		// Try "value" as a single node.
		var single struct {
			Tag   string `json:"tag"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if err2 := json.Unmarshal(obj.Value, &single); err2 == nil && strings.EqualFold(single.Tag, "UniqueIdentifier") {
			return single.Value, nil
		}
	}

	// Shape 2: top-level array.
	var arr []struct {
		Tag   string `json:"tag"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &arr); err == nil {
		for _, n := range arr {
			if strings.EqualFold(n.Tag, "UniqueIdentifier") {
				return n.Value, nil
			}
		}
	}

	return "", fmt.Errorf("UniqueIdentifier not found in KMS Create response: %s", truncate(string(data), 256))
}

// truncate returns at most n characters of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

