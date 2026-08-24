package crypto

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	kmipJSONOperationEncrypt = "Encrypt"
	kmipJSONOperationDecrypt = "Decrypt"
	keyWrapBlockCipherMode   = "NISTKeyWrap"
	keyWrapAlgorithm         = "AES"
)

var defaultKeyWrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

type cosmianKMIPJSONManager struct {
	state    *cosmianKeyState
	client   *http.Client
	endpoint string
	closed   bool
	mu       sync.RWMutex
}

func newCosmianKMIPJSONManager(state *cosmianKeyState) (KeyManager, error) {
	u, err := url.Parse(state.opts.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("kms: invalid Cosmian HTTP endpoint %q: %w", state.opts.Endpoint, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("kms: Cosmian HTTP endpoint must include scheme and host: %s", state.opts.Endpoint)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		if !strings.EqualFold(u.Scheme, "http") {
			return nil, fmt.Errorf("kms: Cosmian HTTP endpoint must use https or http: %s", state.opts.Endpoint)
		}
		if !state.opts.InsecureAllowPlaintextTransport {
			return nil, errors.New("kms: Cosmian HTTP endpoint requires insecure_allow_plaintext_transport=true because plaintext DEKs are transmitted without TLS")
		}
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/kmip/2_1"
	}

	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: nil,
	}
	if t, ok := transport.(*http.Transport); ok {
		if strings.EqualFold(u.Scheme, "https") {
			// Clone the TLS config so callers can reuse the original opts without data races.
			if state.opts.TLSConfig != nil {
				t.TLSClientConfig = state.opts.TLSConfig.Clone()
			} else {
				t.TLSClientConfig = defaultTLSConfig()
			}
		}
	}

	client := &http.Client{
		Timeout:   state.timeout,
		Transport: transport,
	}

	return &cosmianKMIPJSONManager{
		state:    state,
		client:   client,
		endpoint: u.String(),
	}, nil
}

func (m *cosmianKMIPJSONManager) Provider() string {
	return m.state.opts.Provider
}

func (m *cosmianKMIPJSONManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("kms: plaintext DEK is empty")
	}
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrProviderUnavailable
	}
	m.mu.RUnlock()

	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	active := m.state.opts.Keys[0]
	ciphertext, returnedKeyID, err := m.encrypt(ctx, active.ID, plaintext)
	if err != nil {
		return nil, err
	}

	// Use the key ID returned from KMS encrypt if available, as it might be the canonical ID
	// that the KMS expects for decrypt operations
	finalKeyID := active.ID
	if returnedKeyID != "" && returnedKeyID != active.ID {
		finalKeyID = returnedKeyID
	}

	version := active.Version
	if ref, ok := m.state.keyLookup[finalKeyID]; ok {
		version = ref.Version
	}

	return &KeyEnvelope{
		KeyID:      finalKeyID,
		KeyVersion: version,
		Provider:   m.Provider(),
		Ciphertext: ciphertext,
	}, nil
}

func (m *cosmianKMIPJSONManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if envelope == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: wrapped key is empty", ErrInvalidEnvelope)
	}
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrProviderUnavailable
	}
	m.mu.RUnlock()

	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	candidates := m.state.candidateKeys(envelope)
	if len(candidates) == 0 {
		return nil, errors.New("kms: no key candidates available for unwrap")
	}

	var lastErr error
	attempts := 0
	maxAttempts := m.state.opts.DualReadWindow + 1
	if maxAttempts <= 0 {
		maxAttempts = len(candidates) // Try all if DualReadWindow is 0 or negative
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if attempts >= maxAttempts {
			break
		}
		data, err := m.decrypt(ctx, candidate, envelope.Ciphertext)
		if err == nil {
			return data, nil
		}
		lastErr = err
		attempts++
	}
	if lastErr == nil {
		lastErr = errors.New("kms: decrypt failed with no attempts recorded")
	}
	return nil, fmt.Errorf("%w: %w", ErrUnwrapFailed, lastErr)
}

func (m *cosmianKMIPJSONManager) ActiveKeyVersion(_ context.Context) (int, error) {
	if len(m.state.opts.Keys) == 0 {
		return 0, errors.New("kms: no keys configured")
	}
	return m.state.opts.Keys[0].Version, nil
}

func (m *cosmianKMIPJSONManager) healthCheckInner(ctx context.Context) error {
	if len(m.state.opts.Keys) == 0 {
		return errors.New("kms: no keys configured")
	}

	ctx, cancel := m.state.withTimeout(ctx)
	defer cancel()

	// For JSON protocol, we'll do a lightweight Get operation via HTTP
	// This verifies connectivity without performing encryption/decryption
	active := m.state.opts.Keys[0]
	req := kmipJSONRequestNode{
		Tag: "Get",
		Value: []kmipJSONRequestNode{
			textStringNode("UniqueIdentifier", active.ID),
		},
	}

	resp, err := m.doRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("kms: health check failed (key ID: %s): %w", active.ID, err)
	}

	// Verify we got a valid response (not an error)
	if strings.EqualFold(resp.Tag, "Error") || strings.EqualFold(resp.Tag, "ErrorResponse") {
		children, _ := resp.children()
		msgNode := findKMIPChild(children, "Message")
		msg := "unknown error"
		if msgNode != nil {
			if v, err := msgNode.stringValue(); err == nil {
				msg = v
			}
		}
		return fmt.Errorf("kms: health check failed (key ID: %s): %s", active.ID, msg)
	}

	return nil
}

func (m *cosmianKMIPJSONManager) Close(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		if tr, ok := m.client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

func (m *cosmianKMIPJSONManager) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return fmt.Errorf("kms: provider closed: %w", ErrProviderUnavailable)
	}
	if m.client == nil {
		return fmt.Errorf("kms: client not initialized: %w", ErrProviderUnavailable)
	}
	return m.healthCheckInner(ctx)
}

func (m *cosmianKMIPJSONManager) encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, string, error) {
	req := kmipJSONRequestNode{
		Tag: kmipJSONOperationEncrypt,
		Value: []kmipJSONRequestNode{
			textStringNode("UniqueIdentifier", keyID),
			cryptographicParametersNode(),
			byteStringNode("Data", plaintext),
			byteStringNode("IVCounterNonce", defaultKeyWrapIV),
		},
	}

	resp, err := m.doRequest(ctx, req)
	if err != nil {
		return nil, "", err
	}

	children, err := resp.children()
	if err != nil {
		return nil, "", err
	}

	dataNode := findKMIPChild(children, "Data")
	if dataNode == nil {
		return nil, "", errors.New("kms: Encrypt response missing Data field")
	}
	ciphertext, err := dataNode.bytesValue()
	if err != nil {
		return nil, "", fmt.Errorf("kms: invalid encrypt response ciphertext: %w", err)
	}

	keyNode := findKMIPChild(children, "UniqueIdentifier")
	keyValue := keyID
	if keyNode != nil {
		if v, err := keyNode.stringValue(); err == nil && v != "" {
			keyValue = v
		}
	}

	// Note: For NIST Key Wrap, the IVCounterNonce is typically not returned in the response
	// and should be the same fixed value (0xA6A6A6A6A6A6A6A6) for both encrypt and decrypt.
	// We use defaultKeyWrapIV for both operations, which should be correct.

	return ciphertext, keyValue, nil
}

func (m *cosmianKMIPJSONManager) decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	req := kmipJSONRequestNode{
		Tag: kmipJSONOperationDecrypt,
		Value: []kmipJSONRequestNode{
			textStringNode("UniqueIdentifier", keyID),
			cryptographicParametersNode(),
			byteStringNode("Data", ciphertext),
			byteStringNode("IVCounterNonce", defaultKeyWrapIV),
		},
	}

	resp, err := m.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	children, err := resp.children()
	if err != nil {
		return nil, err
	}

	dataNode := findKMIPChild(children, "Data")
	if dataNode == nil {
		return nil, errors.New("kms: Decrypt response missing Data field")
	}
	plaintext, err := dataNode.bytesValue()
	if err != nil {
		return nil, fmt.Errorf("kms: invalid decrypt response payload: %w", err)
	}
	return plaintext, nil
}

func (m *cosmianKMIPJSONManager) doRequest(ctx context.Context, payload kmipJSONRequestNode) (*kmipJSONResponseNode, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kms: failed to marshal KMIP JSON request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kms: failed to create KMIP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms: KMIP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kms: failed to read KMIP response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kms: KMIP request failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var node kmipJSONResponseNode
	if err := json.Unmarshal(respBody, &node); err != nil {
		return nil, fmt.Errorf("kms: invalid KMIP JSON response: %w", err)
	}
	// Check if response indicates an error (KMIP error responses have tag "Error" or "ErrorResponse")
	if strings.EqualFold(node.Tag, "Error") || strings.EqualFold(node.Tag, "ErrorResponse") {
		// Try to extract error message from response
		children, _ := node.children()
		msgNode := findKMIPChild(children, "Message")
		msg := "unknown error"
		if msgNode != nil {
			if v, err := msgNode.stringValue(); err == nil {
				msg = v
			}
		}
		return nil, fmt.Errorf("kms: KMIP operation failed: %s", msg)
	}
	return &node, nil
}

func cryptographicParametersNode() kmipJSONRequestNode {
	return kmipJSONRequestNode{
		Tag: "CryptographicParameters",
		Value: []kmipJSONRequestNode{
			enumNode("BlockCipherMode", keyWrapBlockCipherMode),
			enumNode("CryptographicAlgorithm", keyWrapAlgorithm),
		},
	}
}

type kmipJSONRequestNode struct {
	Tag   string      `json:"tag"`
	Type  string      `json:"type,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

type kmipJSONResponseNode struct {
	Tag   string          `json:"tag"`
	Type  string          `json:"type,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func (n *kmipJSONResponseNode) children() ([]kmipJSONResponseNode, error) {
	if n == nil || len(n.Value) == 0 {
		return nil, nil
	}
	data := bytes.TrimSpace(n.Value)
	if len(data) == 0 || data[0] != '[' {
		return nil, nil
	}
	var nodes []kmipJSONResponseNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("kms: malformed KMIP JSON structure: %w", err)
	}
	return nodes, nil
}

func (n *kmipJSONResponseNode) stringValue() (string, error) {
	if n == nil || len(n.Value) == 0 {
		return "", nil
	}
	var val string
	if err := json.Unmarshal(n.Value, &val); err != nil {
		return "", err
	}
	return val, nil
}

func (n *kmipJSONResponseNode) bytesValue() ([]byte, error) {
	if n == nil || len(n.Value) == 0 {
		return nil, nil
	}
	data := bytes.TrimSpace(n.Value)
	if len(data) == 0 {
		return nil, nil
	}
	// Empty arrays are treated as nil byte slices.
	if len(data) == 2 && data[0] == '[' && data[1] == ']' {
		return nil, nil
	}
	if data[0] != '"' {
		return nil, fmt.Errorf("unexpected KMIP value: %s", string(data))
	}
	var hexValue string
	if err := json.Unmarshal(n.Value, &hexValue); err != nil {
		return nil, err
	}
	if hexValue == "" {
		return nil, nil
	}
	return hex.DecodeString(hexValue)
}

func textStringNode(tag, value string) kmipJSONRequestNode {
	return kmipJSONRequestNode{
		Tag:   tag,
		Type:  "TextString",
		Value: value,
	}
}

func enumNode(tag, value string) kmipJSONRequestNode {
	return kmipJSONRequestNode{
		Tag:   tag,
		Type:  "Enumeration",
		Value: value,
	}
}

func byteStringNode(tag string, data []byte) kmipJSONRequestNode {
	val := ""
	if len(data) > 0 {
		val = strings.ToUpper(hex.EncodeToString(data))
	}
	return kmipJSONRequestNode{
		Tag:   tag,
		Type:  "ByteString",
		Value: val,
	}
}

func findKMIPChild(children []kmipJSONResponseNode, tag string) *kmipJSONResponseNode {
	for i := range children {
		if strings.EqualFold(children[i].Tag, tag) {
			return &children[i]
		}
	}
	return nil
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
