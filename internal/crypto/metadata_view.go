package crypto

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

// sealMetadataBlob encrypts gateway metadata and leaves protected standard
// headers in clear metadata for HEAD and backend-copy operations.
func (e *engine) sealMetadataBlob(encMetadata map[string]string) error {
	protected := make(map[string]string)
	for _, spec := range ProtectedStandardKeys() {
		if value := metadataValueFold(encMetadata, spec.Canonical); value != "" {
			protected[spec.Canonical] = value
		}
	}
	blob, err := e.encryptMetadata(encMetadata)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}
	for key := range encMetadata {
		if isEncryptionPayloadMetadata(key) {
			delete(encMetadata, key)
		}
	}
	encMetadata[MetaEncrypted] = "true"
	encMetadata[MetaEncryptedMetadata] = blob
	for key, value := range protected {
		encMetadata[key] = value
	}
	return nil
}

// stampProtectedStandard copies caller-provided native standard headers into
// their protected metadata names. It deliberately ignores gateway-owned input.
func stampProtectedStandard(dst, caller map[string]string) {
	standard, _ := objectmeta.Split(caller)
	for _, spec := range ProtectedStandardKeys() {
		if value := standard.Get(spec.Header); value != "" {
			dst[spec.Canonical] = value
		}
	}
}

func dropGatewayReserved(meta map[string]string) {
	for key := range meta {
		if IsGatewayReservedKey(key) {
			delete(meta, key)
		}
	}
}

// plaintextMetadataView returns the client-facing metadata portion of an
// expanded encryption map. Canonical protected values win over aliases.
func plaintextMetadataView(expanded map[string]string, plainLen int64, originalETag string) map[string]string {
	out := make(map[string]string, len(expanded)+2)
	for key, value := range expanded {
		if IsGatewayReservedKey(key) || strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "ETag") {
			continue
		}
		// Preserve native standard headers supplied by the backend as a legacy
		// fallback, while always emitting their canonical spelling.
		if objectmeta.IsStandard(key) {
			out[http.CanonicalHeaderKey(key)] = value
		} else {
			out[key] = value
		}
	}
	for _, spec := range ProtectedStandardKeys() {
		value := metadataValueFold(expanded, spec.Canonical)
		if value == "" && spec.Compact != "" {
			value = metadataValueFold(expanded, spec.Compact)
		}
		if value == "" {
			for _, legacy := range spec.Legacy {
				if value = metadataValueFold(expanded, legacy); value != "" {
					break
				}
			}
		}
		if value == "" {
			value = metadataValueFold(expanded, spec.Header)
		}
		if value != "" {
			out[spec.Header] = value
		}
	}
	if plainLen >= 0 {
		out["Content-Length"] = strconv.FormatInt(plainLen, 10)
	}
	if originalETag != "" {
		out["ETag"] = originalETag
	}
	return out
}

// PlaintextMetadataView exposes the client-facing metadata projection for API
// handlers that need to merge it with backend response metadata.
func PlaintextMetadataView(expanded map[string]string, plainLen int64, originalETag string) map[string]string {
	return plaintextMetadataView(expanded, plainLen, originalETag)
}

func metadataValueFold(meta map[string]string, name string) string {
	for key, value := range meta {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
