// Package objectmeta owns the client-visible standard S3 object headers.
package objectmeta

import (
	"net/http"
	"strings"
)

// Standard is the persisted client-visible standard metadata model.
type Standard struct {
	ContentType, CacheControl, ContentDisposition string
	ContentEncoding, ContentLanguage, Expires     string
}

// Names is the canonical, fixed-order list of supported standard headers.
var Names = [...]string{"Content-Type", "Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Expires"}

func FromHeader(h http.Header) Standard {
	var s Standard
	for _, name := range Names {
		for key, values := range h {
			if strings.EqualFold(key, name) && len(values) > 0 {
				s = s.Set(name, values[0])
			}
		}
	}
	return s
}

func Split(meta map[string]string) (Standard, map[string]string) {
	var s Standard
	remainder := make(map[string]string, len(meta))
	for k, v := range meta {
		if isStandard(k) {
			s = s.Set(k, v)
		} else {
			remainder[k] = v
		}
	}
	return s, remainder
}

func (s Standard) Get(name string) string {
	switch strings.ToLower(name) {
	case "content-type":
		return s.ContentType
	case "cache-control":
		return s.CacheControl
	case "content-disposition":
		return s.ContentDisposition
	case "content-encoding":
		return s.ContentEncoding
	case "content-language":
		return s.ContentLanguage
	case "expires":
		return s.Expires
	}
	return ""
}

func (s Standard) Set(name, value string) Standard {
	switch strings.ToLower(name) {
	case "content-type":
		s.ContentType = value
	case "cache-control":
		s.CacheControl = value
	case "content-disposition":
		s.ContentDisposition = value
	case "content-encoding":
		s.ContentEncoding = value
	case "content-language":
		s.ContentLanguage = value
	case "expires":
		s.Expires = value
	}
	return s
}

func (s Standard) ApplyTo(meta map[string]string) {
	for _, name := range Names {
		if v := s.Get(name); v != "" {
			meta[name] = v
		}
	}
}

func (s Standard) Overlay(o Standard) Standard {
	for _, name := range Names {
		if v := o.Get(name); v != "" {
			s = s.Set(name, v)
		}
	}
	return s
}

func NormalizeBackendKeys(meta map[string]string) map[string]string {
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			out[strings.ToLower(k)] = v
		} else if strings.EqualFold(k, "etag") {
			out["ETag"] = v
		} else {
			out[http.CanonicalHeaderKey(k)] = v
		}
	}
	return out
}

func isStandard(name string) bool {
	for _, n := range Names {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// IsStandard reports whether name is one of the client-visible standard
// metadata fields owned by this package.
func IsStandard(name string) bool { return isStandard(name) }
