// keymanager_cosmian_json_test.go — unit tests for the KMIP JSON helper layer.
// These test the pure helper functions without requiring a live Cosmian KMS.
// V0.6-QA-2: unit-test coverage gap closure.
package crypto

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- kmipJSONResponseNode helpers ------------------------------------------

func makeResponseNode(tag, typ, value string) kmipJSONResponseNode {
	raw, _ := json.Marshal(value)
	return kmipJSONResponseNode{
		Tag:   tag,
		Type:  typ,
		Value: json.RawMessage(raw),
	}
}

func makeArrayNode(tag string, children []kmipJSONResponseNode) kmipJSONResponseNode {
	raw, _ := json.Marshal(children)
	return kmipJSONResponseNode{
		Tag:   tag,
		Value: json.RawMessage(raw),
	}
}

// TestKMIPResponseNode_Children_Nil verifies nil/empty Value returns nil children.
func TestKMIPResponseNode_Children_Nil(t *testing.T) {
	var n *kmipJSONResponseNode
	ch, err := n.children()
	if err != nil {
		t.Errorf("nil node children: unexpected error: %v", err)
	}
	if ch != nil {
		t.Errorf("nil node children: expected nil, got %v", ch)
	}

	empty := &kmipJSONResponseNode{}
	ch2, err := empty.children()
	if err != nil {
		t.Errorf("empty node children: unexpected error: %v", err)
	}
	if ch2 != nil {
		t.Errorf("empty node children: expected nil, got %v", ch2)
	}
}

// TestKMIPResponseNode_Children_Array verifies valid array is parsed.
func TestKMIPResponseNode_Children_Array(t *testing.T) {
	inner := []kmipJSONResponseNode{
		{Tag: "Foo", Type: "TextString"},
		{Tag: "Bar", Type: "Integer"},
	}
	parent := makeArrayNode("Parent", inner)

	ch, err := parent.children()
	if err != nil {
		t.Fatalf("children() error: %v", err)
	}
	if len(ch) != 2 {
		t.Errorf("expected 2 children, got %d", len(ch))
	}
	if ch[0].Tag != "Foo" {
		t.Errorf("ch[0].Tag = %q, want Foo", ch[0].Tag)
	}
}

// TestKMIPResponseNode_Children_NotArray verifies non-array value returns nil.
func TestKMIPResponseNode_Children_NotArray(t *testing.T) {
	n := makeResponseNode("Key", "TextString", "just a string")
	ch, err := n.children()
	if err != nil {
		t.Errorf("non-array children: unexpected error: %v", err)
	}
	if ch != nil {
		t.Errorf("non-array children: expected nil")
	}
}

// TestKMIPResponseNode_StringValue verifies string extraction.
func TestKMIPResponseNode_StringValue(t *testing.T) {
	n := makeResponseNode("Name", "TextString", "hello")
	s, err := n.stringValue()
	if err != nil {
		t.Fatalf("stringValue() error: %v", err)
	}
	if s != "hello" {
		t.Errorf("stringValue() = %q, want %q", s, "hello")
	}

	var nilN *kmipJSONResponseNode
	s2, err := nilN.stringValue()
	if err != nil {
		t.Fatalf("nil node stringValue() error: %v", err)
	}
	if s2 != "" {
		t.Errorf("nil node stringValue() = %q, want \"\"", s2)
	}
}

// TestKMIPResponseNode_BytesValue_HexString verifies hex-encoded bytes.
func TestKMIPResponseNode_BytesValue_HexString(t *testing.T) {
	hexStr := "0102030405060708"
	raw, _ := json.Marshal(hexStr)
	n := kmipJSONResponseNode{
		Tag:   "KeyValue",
		Type:  "ByteString",
		Value: json.RawMessage(raw),
	}
	got, err := n.bytesValue()
	if err != nil {
		t.Fatalf("bytesValue() error: %v", err)
	}
	expected, _ := hex.DecodeString(hexStr)
	if string(got) != string(expected) {
		t.Errorf("bytesValue() = %x, want %x", got, expected)
	}
}

// TestKMIPResponseNode_BytesValue_Empty verifies empty/nil value handling.
func TestKMIPResponseNode_BytesValue_Empty(t *testing.T) {
	// nil node
	var n *kmipJSONResponseNode
	b, err := n.bytesValue()
	if err != nil {
		t.Errorf("nil node bytesValue(): %v", err)
	}
	if b != nil {
		t.Error("nil node bytesValue() should return nil")
	}

	// empty array
	n2 := kmipJSONResponseNode{Value: json.RawMessage("[]")}
	b2, err := n2.bytesValue()
	if err != nil {
		t.Errorf("empty array bytesValue(): %v", err)
	}
	if b2 != nil {
		t.Error("empty array bytesValue() should return nil")
	}
}

// TestKMIPResponseNode_BytesValue_NonStringValue verifies error on unexpected format.
func TestKMIPResponseNode_BytesValue_NonStringValue(t *testing.T) {
	// Non-quoted, non-array value — should error.
	n := kmipJSONResponseNode{
		Tag:   "Bad",
		Value: json.RawMessage("123"),
	}
	_, err := n.bytesValue()
	if err == nil {
		t.Error("expected error for non-string KMIP value, got nil")
	}
}

// ---- Builder helpers --------------------------------------------------------

func TestTextStringNode(t *testing.T) {
	n := textStringNode("MyTag", "myValue")
	if n.Tag != "MyTag" {
		t.Errorf("Tag = %q, want MyTag", n.Tag)
	}
	if n.Type != "TextString" {
		t.Errorf("Type = %q, want TextString", n.Type)
	}
	if n.Value != "myValue" {
		t.Errorf("Value = %q, want myValue", n.Value)
	}
}

func TestEnumNode(t *testing.T) {
	n := enumNode("BlockCipherMode", "NISTKeyWrap")
	if n.Type != "Enumeration" {
		t.Errorf("Type = %q, want Enumeration", n.Type)
	}
	if n.Value != "NISTKeyWrap" {
		t.Errorf("Value = %q, want NISTKeyWrap", n.Value)
	}
}

func TestByteStringNode(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	n := byteStringNode("Payload", data)
	if n.Type != "ByteString" {
		t.Errorf("Type = %q, want ByteString", n.Type)
	}
	expected := strings.ToUpper(hex.EncodeToString(data))
	if n.Value.(string) != expected {
		t.Errorf("Value = %q, want %q", n.Value, expected)
	}

	// Empty data should produce empty string.
	n2 := byteStringNode("Empty", nil)
	if n2.Value.(string) != "" {
		t.Errorf("empty data Value = %q, want \"\"", n2.Value)
	}
}

func TestCryptographicParametersNode(t *testing.T) {
	n := cryptographicParametersNode()
	if n.Tag != "CryptographicParameters" {
		t.Errorf("Tag = %q, want CryptographicParameters", n.Tag)
	}
	children, ok := n.Value.([]kmipJSONRequestNode)
	if !ok {
		t.Fatalf("Value is not []kmipJSONRequestNode")
	}
	if len(children) != 2 {
		t.Errorf("expected 2 children, got %d", len(children))
	}
}

// ---- findKMIPChild ----------------------------------------------------------

func TestFindKMIPChild(t *testing.T) {
	children := []kmipJSONResponseNode{
		{Tag: "Alpha"},
		{Tag: "Beta"},
		{Tag: "Gamma"},
	}

	found := findKMIPChild(children, "beta")
	if found == nil {
		t.Fatal("findKMIPChild: should find Beta (case-insensitive)")
	}
	if found.Tag != "Beta" {
		t.Errorf("found.Tag = %q, want Beta", found.Tag)
	}

	notFound := findKMIPChild(children, "Delta")
	if notFound != nil {
		t.Error("findKMIPChild: should return nil for missing tag")
	}

	// Empty list.
	if findKMIPChild(nil, "Alpha") != nil {
		t.Error("findKMIPChild(nil): should return nil")
	}
}

// ---- defaultTLSConfig -------------------------------------------------------

func TestDefaultTLSConfig(t *testing.T) {
	cfg := defaultTLSConfig()
	if cfg == nil {
		t.Fatal("defaultTLSConfig() returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
}

// ---- newCosmianKMIPJSONManager error paths ----------------------------------

func TestNewCosmianKMIPJSONManager_InvalidEndpoint(t *testing.T) {
	// Missing scheme/host should fail.
	state := &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint: "not-a-url",
		},
	}
	_, err := newCosmianKMIPJSONManager(state)
	if err == nil {
		t.Error("expected error for invalid endpoint (no scheme/host)")
	}
}

func TestNewCosmianKMIPJSONManager_EmptyPath(t *testing.T) {
	// An endpoint with scheme/host but empty path should auto-set path to /kmip/2_1.
	state := &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint: "https://kms.example.com",
			Provider: "cosmian-kmip-json",
		},
		timeout: 30_000_000_000, // 30s in nanoseconds
	}
	m, err := newCosmianKMIPJSONManager(state)
	if err != nil {
		t.Fatalf("newCosmianKMIPJSONManager: unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	// Verify Provider() works.
	if got := m.Provider(); got != "cosmian-kmip-json" {
		t.Errorf("Provider() = %q, want cosmian-kmip-json", got)
	}
}

func TestNewCosmianKMIPJSONManager_HTTPRequiresExplicitOptIn(t *testing.T) {
	state := &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint: "http://kms.example.com/kmip/2_1",
			Provider: "cosmian-kmip-http",
		},
		timeout: 5_000_000_000,
	}
	if _, err := newCosmianKMIPJSONManager(state); err == nil {
		t.Fatal("expected HTTP endpoint to require explicit plaintext transport opt-in")
	}

	state.opts.InsecureAllowPlaintextTransport = true
	if _, err := newCosmianKMIPJSONManager(state); err != nil {
		t.Fatalf("newCosmianKMIPJSONManager (HTTP with opt-in): %v", err)
	}
}

// ---- cosmianKMIPJSONManager method error paths ------------------------------

func makeTestJSONManager(t *testing.T) *cosmianKMIPJSONManager {
	t.Helper()
	state := &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint:                        "http://kms.test.example.com/kmip/2_1",
			Provider:                        "cosmian-kmip-json",
			InsecureAllowPlaintextTransport: true,
			Keys: []KMIPKeyReference{
				{ID: "key-1", Version: 1},
			},
			DualReadWindow: 1,
		},
		timeout: 5_000_000_000,
		keyLookup: map[string]KMIPKeyReference{
			"key-1": {ID: "key-1", Version: 1},
		},
		versionLookup: map[int]KMIPKeyReference{
			1: {ID: "key-1", Version: 1},
		},
	}
	m, err := newCosmianKMIPJSONManager(state)
	if err != nil {
		t.Fatalf("newCosmianKMIPJSONManager: %v", err)
	}
	return m.(*cosmianKMIPJSONManager)
}

func TestCosmianKMIPJSON_UnwrapKey_NilEnvelope(t *testing.T) {
	m := makeTestJSONManager(t)
	_, err := m.UnwrapKey(nil, nil, nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error for nil envelope")
	}
}

func TestCosmianKMIPJSON_UnwrapKey_EmptyEnvelope(t *testing.T) {
	m := makeTestJSONManager(t)
	env := &KeyEnvelope{Ciphertext: nil}
	_, err := m.UnwrapKey(nil, env, nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error for empty ciphertext")
	}
}

func TestCosmianKMIPJSON_ActiveKeyVersion(t *testing.T) {
	m := makeTestJSONManager(t)
	// Should return the version from keys[0].
	ver, err := m.ActiveKeyVersion(nil) //nolint:staticcheck
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if ver != 1 {
		t.Errorf("ActiveKeyVersion = %d, want 1", ver)
	}
}

func TestCosmianKMIPJSON_ActiveKeyVersion_NoKeys(t *testing.T) {
	state := &cosmianKeyState{
		opts:    CosmianKMIPOptions{Endpoint: "https://kms.test.example.com"},
		timeout: 5_000_000_000,
	}
	m, err := newCosmianKMIPJSONManager(state)
	if err != nil {
		t.Fatalf("newCosmianKMIPJSONManager: %v", err)
	}
	_, err = m.(*cosmianKMIPJSONManager).ActiveKeyVersion(nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error when no keys configured")
	}
}

func TestCosmianKMIPJSON_Close(t *testing.T) {
	m := makeTestJSONManager(t)
	// Close should not error.
	if err := m.Close(nil); err != nil { //nolint:staticcheck
		t.Errorf("Close: %v", err)
	}
	// After Close, operations should fail.
	_, err := m.UnwrapKey(nil, &KeyEnvelope{Ciphertext: []byte{1}}, nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error after Close")
	}
}

func TestCosmianKMIPJSON_Provider(t *testing.T) {
	m := makeTestJSONManager(t)
	got := m.Provider()
	if got != "cosmian-kmip-json" {
		t.Errorf("Provider() = %q, want cosmian-kmip-json", got)
	}
}

func TestCosmianKMIPJSON_WrapKey_EmptyPlaintext(t *testing.T) {
	m := makeTestJSONManager(t)
	_, err := m.WrapKey(nil, nil, nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error for empty plaintext")
	}
}

func TestCosmianKMIPJSON_HealthCheck_NoKeys(t *testing.T) {
	state := &cosmianKeyState{
		opts:    CosmianKMIPOptions{Endpoint: "https://kms.test.example.com"},
		timeout: 5_000_000_000,
	}
	m, err := newCosmianKMIPJSONManager(state)
	if err != nil {
		t.Fatalf("newCosmianKMIPJSONManager: %v", err)
	}
	// HealthCheck should error when no keys configured.
	err = m.(*cosmianKMIPJSONManager).HealthCheck(nil) //nolint:staticcheck
	if err == nil {
		t.Error("expected error from HealthCheck with no keys")
	}
}

// ---- endpointHasScheme ------------------------------------------------------

func TestEndpointHasScheme(t *testing.T) {
	tests := []struct {
		endpoint string
		want     bool
	}{
		{"https://kms.example.com", true},
		{"http://localhost:9990", true},
		{"", false},
		{"kms.example.com:5696", false},  // no scheme
		{"kmip://kms.example.com", true}, // kmip scheme
		{"://broken", false},             // broken URL
	}
	for _, tt := range tests {
		got := endpointHasScheme(tt.endpoint)
		if got != tt.want {
			t.Errorf("endpointHasScheme(%q) = %v, want %v", tt.endpoint, got, tt.want)
		}
	}
}

// ---- WrapKey with mock HTTP server ------------------------------------------

func makeJSONManagerWithServer(t *testing.T, handler http.HandlerFunc) (*cosmianKMIPJSONManager, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	state := &cosmianKeyState{
		opts: CosmianKMIPOptions{
			Endpoint:                        srv.URL + "/kmip/2_1",
			Provider:                        "cosmian-kmip-json",
			InsecureAllowPlaintextTransport: true,
			Keys: []KMIPKeyReference{
				{ID: "key-1", Version: 1},
			},
		},
		timeout: 5_000_000_000,
		keyLookup: map[string]KMIPKeyReference{
			"key-1": {ID: "key-1", Version: 1},
		},
		versionLookup: map[int]KMIPKeyReference{
			1: {ID: "key-1", Version: 1},
		},
	}
	m, err := newCosmianKMIPJSONManager(state)
	if err != nil {
		t.Fatalf("newCosmianKMIPJSONManager: %v", err)
	}
	return m.(*cosmianKMIPJSONManager), srv
}

func TestCosmianKMIPJSON_WrapKey_Success(t *testing.T) {
	// The KMIP JSON Encrypt response format:
	// {"tag":"Encrypt","value":[{"tag":"Data","type":"ByteString","value":"DEADBEEF"},{"tag":"UniqueIdentifier","type":"TextString","value":"key-1"}]}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a canned KMIP Encrypt response with 4 hex bytes.
		w.Write([]byte(`{"tag":"Encrypt","value":[{"tag":"Data","type":"ByteString","value":"DEADBEEF"},{"tag":"UniqueIdentifier","type":"TextString","value":"key-1"}]}`))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	ctx := context.Background()
	plaintext := make([]byte, 32)
	env, err := m.WrapKey(ctx, plaintext, nil)
	if err != nil {
		t.Fatalf("WrapKey with mock: %v", err)
	}
	if env == nil {
		t.Fatal("expected non-nil envelope")
	}
	if env.Provider != "cosmian-kmip-json" {
		t.Errorf("Provider = %q, want cosmian-kmip-json", env.Provider)
	}
}

func TestCosmianKMIPJSON_WrapKey_HTTPError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	_, err := m.WrapKey(context.Background(), make([]byte, 32), nil)
	if err == nil {
		t.Error("expected error for HTTP 500 response")
	}
}

func TestCosmianKMIPJSON_HealthCheck_Success(t *testing.T) {
	// HealthCheck calls healthCheckInner which calls encrypt.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tag":"Encrypt","value":[{"tag":"Data","type":"ByteString","value":"DEADBEEF"},{"tag":"UniqueIdentifier","type":"TextString","value":"key-1"}]}`))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	err := m.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck with mock: %v", err)
	}
}

func TestCosmianKMIPJSON_UnwrapKey_Success(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a Decrypt response with 32 bytes of zeros.
		zeroes := strings.ToUpper(strings.Repeat("00", 32))
		w.Write([]byte(`{"tag":"Decrypt","value":[{"tag":"Data","type":"ByteString","value":"` + zeroes + `"}]}`))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	env := &KeyEnvelope{
		Provider:   "cosmian-kmip-json",
		KeyID:      "key-1",
		KeyVersion: 1,
		Ciphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF}, // fake ciphertext
	}
	plaintext, err := m.UnwrapKey(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("UnwrapKey with mock: %v", err)
	}
	if len(plaintext) != 32 {
		t.Errorf("expected 32 bytes plaintext, got %d", len(plaintext))
	}
}

func TestCosmianKMIPJSON_DoRequest_KMIPError(t *testing.T) {
	// Server returns a KMIP error response.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tag":"Error","value":[{"tag":"Message","type":"TextString","value":"Key not found"}]}`))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	_, err := m.WrapKey(context.Background(), make([]byte, 32), nil)
	if err == nil {
		t.Error("expected error from KMIP error response")
	}
	if !strings.Contains(err.Error(), "Key not found") {
		t.Errorf("error should contain KMIP message: %v", err)
	}
}

func TestCosmianKMIPJSON_DoRequest_InvalidJSON(t *testing.T) {
	// Server returns invalid JSON.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json at all!"))
	})
	m, _ := makeJSONManagerWithServer(t, handler)

	_, err := m.WrapKey(context.Background(), make([]byte, 32), nil)
	if err == nil {
		t.Error("expected error from invalid JSON response")
	}
}

// ---- cosmianKeyState.withTimeout --------------------------------------------

func TestCosmianKeyState_WithTimeout_ZeroTimeout(t *testing.T) {
	state := &cosmianKeyState{
		opts:    CosmianKMIPOptions{},
		timeout: 0, // zero → no timeout
	}
	ctx, cancel := state.withTimeout(context.Background())
	defer cancel()
	// Should return the same context without a deadline.
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Error("expected no deadline for zero timeout")
	}
}

func TestCosmianKeyState_WithTimeout_NilCtx(t *testing.T) {
	state := &cosmianKeyState{
		opts:    CosmianKMIPOptions{},
		timeout: 5_000_000_000,
	}
	// nil ctx → should use context.Background() internally.
	ctx, cancel := state.withTimeout(nil)
	defer cancel()
	if ctx == nil {
		t.Error("expected non-nil context")
	}
}

// ---- prepareCosmianKeyState -------------------------------------------------

func TestPrepareCosmianKeyState_Errors(t *testing.T) {
	// Missing endpoint.
	_, err := prepareCosmianKeyState(CosmianKMIPOptions{
		Endpoint: "",
		Keys:     []KMIPKeyReference{{ID: "k1"}},
	})
	if err == nil {
		t.Error("expected error for empty endpoint")
	}

	// Missing keys.
	_, err = prepareCosmianKeyState(CosmianKMIPOptions{
		Endpoint: "https://kms.example.com",
		Keys:     nil,
	})
	if err == nil {
		t.Error("expected error for no keys")
	}

	// Key with missing ID.
	_, err = prepareCosmianKeyState(CosmianKMIPOptions{
		Endpoint: "https://kms.example.com",
		Keys:     []KMIPKeyReference{{ID: ""}},
	})
	if err == nil {
		t.Error("expected error for key with missing id")
	}
}

func TestPrepareCosmianKeyState_VersionAutoAssign(t *testing.T) {
	state, err := prepareCosmianKeyState(CosmianKMIPOptions{
		Endpoint: "https://kms.example.com",
		Keys: []KMIPKeyReference{
			{ID: "key-a", Version: 0}, // should get version=1
			{ID: "key-b", Version: 0}, // should get version=2
		},
	})
	if err != nil {
		t.Fatalf("prepareCosmianKeyState: %v", err)
	}
	if state.versionLookup[1].ID != "key-a" {
		t.Errorf("version 1 should map to key-a, got %s", state.versionLookup[1].ID)
	}
	if state.versionLookup[2].ID != "key-b" {
		t.Errorf("version 2 should map to key-b, got %s", state.versionLookup[2].ID)
	}
}
