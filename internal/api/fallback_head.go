package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// restoreFallbackHead reads one bounded prefix from the same request-scoped
// client. ETag is a backend validator, not a cryptographic integrity proof.
func restoreFallbackHead(ctx context.Context, client s3.Client, view *objectView) (map[string]string, error) {
	head := view.Raw
	headVersion := head["x-amz-version-id"]
	version := view.VersionID
	if version != nil && *version != "" && headVersion != "" && *version != headVersion {
		return nil, fmt.Errorf("fallback head version mismatch")
	}
	if (version == nil || *version == "") && headVersion != "" {
		version = &headVersion
	}
	immutable := version != nil && *version != "" && *version != "null"
	etag := head["ETag"]
	if !immutable && etag == "" {
		return nil, fmt.Errorf("fallback head missing identity")
	}
	rangeValue := fmt.Sprintf("bytes=0-%d", crypto.MaxFallbackPrefixBytes-1)
	var body io.ReadCloser
	var got map[string]string
	var err error
	if immutable {
		body, got, err = client.GetObject(ctx, view.Bucket, view.Key, version, &rangeValue)
	} else {
		conditional, ok := client.(s3.ConditionalObjectReader)
		if !ok {
			return nil, fmt.Errorf("fallback conditional read: %w", s3.ErrNotImplemented)
		}
		body, got, err = conditional.GetObjectIfMatch(ctx, view.Bucket, view.Key, version, &rangeValue, etag, s3.ObjectReadOptions{})
	}
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, &objectBackendError{bucket: view.Bucket, key: view.Key, method: "GET", err: err}
	}
	if body == nil {
		return nil, fmt.Errorf("fallback read missing body")
	}
	defer body.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if got["ETag"] == "" || (etag != "" && got["ETag"] != etag) {
		return nil, fmt.Errorf("fallback ETag mismatch")
	}
	if version != nil && *version != "" && got["x-amz-version-id"] != *version {
		return nil, fmt.Errorf("fallback version mismatch")
	}
	if headVersion != "" && headVersion != got["x-amz-version-id"] {
		return nil, fmt.Errorf("fallback version changed")
	}
	if headVersion == "" && (version == nil || *version == "") && got["x-amz-version-id"] != "" {
		return nil, fmt.Errorf("fallback version changed")
	}
	total, err := strconv.ParseInt(head["Content-Length"], 10, 64)
	if err != nil || total <= 0 {
		return nil, fmt.Errorf("fallback invalid object length")
	}
	end := total - 1
	if end >= crypto.MaxFallbackPrefixBytes {
		end = crypto.MaxFallbackPrefixBytes - 1
	}
	wantRange := fmt.Sprintf("bytes 0-%d/%d", end, total)
	if got["Content-Range"] != wantRange {
		return nil, fmt.Errorf("fallback invalid content range")
	}
	length, err := strconv.ParseInt(got["Content-Length"], 10, 64)
	if err != nil || length != end+1 {
		return nil, fmt.Errorf("fallback invalid ranged length")
	}
	// Compare all user metadata and standard fields that contribute to projection.
	snapshot := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range m {
			lower := strings.ToLower(k)
			if strings.HasPrefix(lower, "x-amz-meta-") || strings.HasPrefix(lower, "x-amz-object-lock-") || strings.HasPrefix(lower, "x-amz-server-side-encryption") || lower == "x-amz-storage-class" || lower == "x-amz-mp-parts-count" || lower == "x-amz-expiration" || lower == "x-amz-website-redirect-location" || lower == "last-modified" || lower == "content-type" || lower == "cache-control" || lower == "content-disposition" || lower == "content-encoding" || lower == "content-language" || lower == "expires" {
				out[lower] = v
			}
		}
		return out
	}
	a, b := snapshot(head), snapshot(got)
	if len(a) != len(b) {
		return nil, fmt.Errorf("fallback metadata snapshot changed")
	}
	for k, v := range a {
		if other, ok := b[k]; !ok || other != v {
			return nil, fmt.Errorf("fallback metadata snapshot changed")
		}
	}
	data, err := io.ReadAll(io.LimitReader(&fallbackHeadContextReader{ctx: ctx, reader: body}, length+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &objectBackendError{bucket: view.Bucket, key: view.Key, method: http.MethodGet, err: &fallbackHeadStreamError{err: err}}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(data)) != length {
		return nil, fmt.Errorf("fallback truncated ranged body")
	}
	prefix, err := crypto.ReadFallbackV2Prefix(ctx, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return crypto.MergeFallbackV2Metadata(view.Expanded, prefix), nil
}

type fallbackHeadContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *fallbackHeadContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

// Retain typed backend provenance without logging untrusted stream error text.
type fallbackHeadStreamError struct{ err error }

func (*fallbackHeadStreamError) Error() string   { return "fallback prefix stream failed" }
func (e *fallbackHeadStreamError) Unwrap() error { return e.err }
