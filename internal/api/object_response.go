package api

import (
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

var (
	projectedProtectedStandardKeys = crypto.ProtectedStandardKeys()
	projectedReservedMetadataKeys  = func() map[string]struct{} {
		keys := make(map[string]struct{})
		for _, spec := range crypto.MetaKeys() {
			for _, key := range []string{spec.Canonical, spec.Compact} {
				if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
					keys[strings.ToLower(key)] = struct{}{}
				}
			}
			for _, key := range spec.Legacy {
				if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
					keys[strings.ToLower(key)] = struct{}{}
				}
			}
		}
		keys["x-amz-meta-original-content-length"] = struct{}{}
		return keys
	}()
)

type responseShape struct {
	Method                string
	Range                 *byteRange
	VersionID             string
	Overrides             url.Values
	UnsatisfiedRangeTotal int64
	HasUnsatisfiedRange   bool
}
type byteRange struct{ Start, End int64 }

func parseResponseOverrides(r *http.Request) url.Values {
	out := make(url.Values)
	for _, name := range []string{"response-content-type", "response-content-language", "response-expires", "response-cache-control", "response-content-disposition", "response-content-encoding"} {
		if v := r.URL.Query().Get(name); v != "" {
			out.Set(name, v)
		}
	}
	return out
}

func projectObjectHeaders(src objectResponseSource, shape responseShape) (http.Header, error) {
	h := make(http.Header, 16)
	meta := src.Meta
	values := make([]string, 0, len(meta)+16)
	valueCount := 0
	set := func(key, value string) {
		setProjectedHeader(h, key, value, values, &valueCount)
	}
	if src.Class.Encrypted && len(src.Decrypted) > 0 {
		merged := make(map[string]string, len(meta)+len(src.Decrypted))
		for k, v := range meta {
			merged[k] = v
		}
		for k, v := range src.Decrypted {
			merged[k] = v
		}
		meta = merged
	}
	for _, n := range objectmeta.Names {
		if v := projectedStandardValue(n, src); v != "" {
			set(n, v)
		}
	}
	for k, v := range meta {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") {
			if _, reserved := projectedReservedMetadataKeys[lk]; reserved {
				continue
			}
			set(lk, v)
		}
		if strings.HasPrefix(lk, "x-amz-object-lock-") || lk == "last-modified" || lk == "x-amz-storage-class" || lk == "x-amz-mp-parts-count" {
			set(k, v)
		}
	}
	etag := src.BackendETag
	original := metadataValue(meta, crypto.MetaOriginalETag)
	if original == "" && src.Class.Encrypted {
		// Fallback formats carry their authenticated plaintext metadata inside
		// the body, so the original ETag may exist only in Decrypted.
		original = metadataValue(src.Decrypted, "ETag")
	}
	if original != "" {
		etag = quoteETag(original)
	}
	if etag != "" {
		set("ETag", etag)
	}
	if backendVersion := metadataValue(meta, "x-amz-version-id"); backendVersion != "" {
		set("x-amz-version-id", backendVersion)
	} else if shape.VersionID != "" {
		set("x-amz-version-id", shape.VersionID)
	}
	if src.PlainSize >= 0 {
		set("Content-Length", strconv.FormatInt(src.PlainSize, 10))
	}
	if shape.Range != nil {
		set("Content-Range", "bytes "+strconv.FormatInt(shape.Range.Start, 10)+"-"+strconv.FormatInt(shape.Range.End, 10)+"/"+strconv.FormatInt(src.PlainSize, 10))
		set("Content-Length", strconv.FormatInt(shape.Range.End-shape.Range.Start+1, 10))
	}
	if shape.HasUnsatisfiedRange {
		set("Content-Range", "bytes */"+strconv.FormatInt(shape.UnsatisfiedRangeTotal, 10))
	}
	if shape.Method == http.MethodGet {
		for k, v := range shape.Overrides {
			if len(v) > 0 {
				switch k {
				case "response-content-type":
					set("Content-Type", v[0])
				case "response-content-language":
					set("Content-Language", v[0])
				case "response-expires":
					set("Expires", v[0])
				case "response-cache-control":
					set("Cache-Control", v[0])
				case "response-content-disposition":
					set("Content-Disposition", v[0])
				case "response-content-encoding":
					set("Content-Encoding", v[0])
				}
			}
		}
	}
	set("Accept-Ranges", "bytes")
	return h, nil
}

func setProjectedHeader(h http.Header, key, value string, values []string, valueCount *int) {
	key = textproto.CanonicalMIMEHeaderKey(key)
	if current, exists := h[key]; exists {
		current[0] = value
		return
	}
	values = values[:*valueCount+1]
	values[*valueCount] = value
	h[key] = values[*valueCount : *valueCount+1 : *valueCount+1]
	*valueCount++
}

// parseObjectRange applies S3's inclusive-range clamping before delegating
// syntax and satisfiability checks to the shared crypto parser. Explicit end
// offsets beyond the plaintext object are clamped to its final byte.
func parseObjectRange(rangeHeader string, totalSize int64) (int64, int64, error) {
	if totalSize > 0 && strings.HasPrefix(rangeHeader, "bytes=") {
		spec := strings.TrimPrefix(rangeHeader, "bytes=")
		if !strings.HasPrefix(spec, "-") {
			parts := strings.Split(spec, "-")
			if len(parts) == 2 && parts[1] != "" {
				end, err := strconv.ParseInt(parts[1], 10, 64)
				if err == nil && end >= totalSize {
					rangeHeader = "bytes=" + parts[0] + "-" + strconv.FormatInt(totalSize-1, 10)
				}
			}
		}
	}
	return crypto.ParseHTTPRangeHeader(rangeHeader, totalSize)
}

func projectedStandardValue(header string, src objectResponseSource) string {
	if src.Class.Encrypted {
		index := -1
		switch header {
		case "Content-Type":
			index = 0
		case "Cache-Control":
			index = 1
		case "Content-Disposition":
			index = 2
		case "Content-Encoding":
			index = 3
		case "Content-Language":
			index = 4
		case "Expires":
			index = 5
		}
		if index >= 0 && index < len(projectedProtectedStandardKeys) {
			spec := projectedProtectedStandardKeys[index]
			if value := metadataValue(src.Decrypted, header); value != "" {
				return value
			}
			if value := metadataValue(src.Meta, spec.Canonical); value != "" {
				return value
			}
			if value := metadataValue(src.Meta, spec.Compact); value != "" {
				return value
			}
			for _, legacy := range spec.Legacy {
				if value := metadataValue(src.Meta, legacy); value != "" {
					return value
				}
			}
		}
	}
	return metadataValue(src.Meta, header)
}

func metadataValue(meta map[string]string, name string) string {
	if value, ok := meta[name]; ok {
		return value
	}
	for key, value := range meta {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func writeObjectHeaders(w http.ResponseWriter, h http.Header) {
	for k, v := range h {
		w.Header()[textproto.CanonicalMIMEHeaderKey(k)] = append([]string(nil), v...)
	}
}
