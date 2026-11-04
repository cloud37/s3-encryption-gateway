package crypto

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// MaxFallbackPrefixBytes includes the four-byte length framing. The prefix is
// plaintext and unauthenticated; this bound does not confer integrity.
const MaxFallbackPrefixBytes = (1 << 20) + 4

// ReadFallbackV2Prefix consumes only the prefix, leaving any ciphertext unread.
// The caller owns and closes the reader.
func ReadFallbackV2Prefix(ctx context.Context, reader io.Reader) (map[string]string, error) {
	if isNilFallbackInput(ctx) || isNilFallbackInput(reader) {
		return nil, fmt.Errorf("fallback-v2: context and reader required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader = &fallbackContextReader{ctx: ctx, reader: reader}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, fmt.Errorf("fallback-v2: invalid prefix framing: %w", err)
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > MaxFallbackPrefixBytes-4 {
		return nil, fmt.Errorf("fallback-v2: metadata length %d exceeds sanity limit", n)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("fallback-v2: truncated metadata: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	meta, err := decodeMetadataFromJSON(data)
	if err != nil || meta == nil {
		return nil, fmt.Errorf("fallback-v2: invalid metadata JSON")
	}
	return meta, nil
}

func isNilFallbackInput(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

type fallbackContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *fallbackContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

// MergeFallbackV2Metadata adds ordinary user fields only. Header values win
// regardless of casing; control and native protected fields never come from
// this unauthenticated source.
func MergeFallbackV2Metadata(header, prefix map[string]string) map[string]string {
	out := make(map[string]string, len(header)+len(prefix))
	seen := make(map[string]bool, len(header))
	for k, v := range header {
		out[k] = v
		seen[strings.ToLower(k)] = true
	}
	for k, v := range prefix {
		lower := strings.ToLower(k)
		if !strings.HasPrefix(lower, "x-amz-meta-") || IsGatewayReservedKey(k) || seen[lower] {
			continue
		}
		out[k] = v
		seen[lower] = true
	}
	return out
}

// Legacy unsealed objects left controls only in the prefix. Permit only the
// controls needed by chunked decryption, never a blob or structural override.
func mergeLegacyFallbackControls(header, prefix map[string]string) map[string]string {
	out := MergeFallbackV2Metadata(header, prefix)
	allowed := []string{MetaKDFParams, MetaChunkedFormat, MetaChunkSize, MetaChunkCount, MetaManifest, MetaIVDerivation, MetaKeyVersion, MetaWrappedKeyCiphertext, MetaKMSKeyID, MetaKMSProvider}
	for _, name := range allowed {
		spec, _ := LookupMetaKey(name)
		present := false
		for k := range header {
			if s, ok := LookupMetaKey(k); ok && s.Canonical == spec.Canonical {
				present = true
				break
			}
		}
		if present {
			continue
		}
		if v, ok := metadataValue(prefix, spec.Canonical); ok {
			out[name] = v
		} else if spec.Compact != "" {
			if v, ok := metadataValue(prefix, spec.Compact); ok {
				out[name] = v
			}
		}
	}
	return out
}
