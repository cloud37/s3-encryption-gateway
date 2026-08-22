package crypto

// TestEncryptionEngineWithCosmianKMIP verifies the full engine encrypt/decrypt
// round-trip when a CosmianKMIPManager is wired in via SetKeyManager.
//
// This is an integration test at the layer below the API handler — it exercises
// the path:
//
//	engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, meta)
//	  → WrapKey (KMIP Encrypt operation)
//	  → stores MetaWrappedKeyCiphertext in object metadata
//
//	engine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, meta)
//	  → UnwrapKey (KMIP Decrypt operation)
//	  → decrypts ciphertext back to original plaintext
//
// The KMIP server is an in-process mock (kmiptest.NewServer); no external
// process or Docker container is required.
//
// Ported from test/cosmian_kms_test.go (deleted when the legacy test/ package
// was removed during the v0.6-QA-4 cleanup). All helpers (testKMIPWrapHandler,
// xorBytes, mustTLSConfigFromPEM) are shared from keymanager_test.go.

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/stretchr/testify/require"
)

func TestEncryptionEngineWithCosmianKMIP(t *testing.T) {
	// Start an in-process KMIP server backed by the xor-based mock handler
	// that is shared across keymanager_test.go tests.
	exec := kmipserver.NewBatchExecutor()
	handler := &testKMIPWrapHandler{}
	exec.Route(kmip.OperationEncrypt, kmipserver.HandleFunc(handler.encrypt))
	exec.Route(kmip.OperationDecrypt, kmipserver.HandleFunc(handler.decrypt))

	addr, ca := kmiptest.NewServer(t, exec)
	tlsCfg := mustTLSConfigFromPEM(t, ca)

	manager, err := NewCosmianKMIPManager(CosmianKMIPOptions{
		Endpoint:       addr,
		Keys:           []KMIPKeyReference{{ID: "test-wrap-key", Version: 1}},
		TLSConfig:      tlsCfg,
		Timeout:        time.Second,
		Provider:       "test-kmip",
		DualReadWindow: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close(context.Background()) })

	engine, err := NewEngine([]byte("fallback-password-123"))
	require.NoError(t, err)
	SetKeyManager(engine, manager)

	plaintext := []byte("cosmian-encryption-test")

	// Encrypt: must stamp MetaEncrypted, MetaWrappedKeyCiphertext, MetaKMSProvider.
	encReader, encMeta, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "true", encMeta[MetaEncrypted])
	require.NotEmpty(t, encMeta[MetaWrappedKeyCiphertext], "wrapped key must be present in metadata")
	require.Equal(t, "test-kmip", encMeta[MetaKMSProvider])

	// Decrypt: must recover original plaintext and surface Content-Type.
	decReader, decMeta, err := engine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, encReader, encMeta)
	require.NoError(t, err)
	require.Equal(t, "text/plain", decMeta["Content-Type"])

	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted, "decrypted content must match original plaintext")
}
