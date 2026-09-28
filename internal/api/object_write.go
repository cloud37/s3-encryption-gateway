package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

type writeMetadata struct {
	User     map[string]string
	Standard objectmeta.Standard
}

func parseWriteMetadata(h http.Header) (writeMetadata, *S3Error) {
	m := writeMetadata{User: make(map[string]string)}
	m.Standard = objectmeta.FromHeader(h)
	for k, values := range h {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, "x-amz-meta-") || len(values) == 0 {
			continue
		}
		if crypto.IsGatewayReservedKey(lk) {
			return writeMetadata{}, &S3Error{Code: "InvalidArgument", Message: "Metadata key " + k + " is reserved by the encryption gateway.", HTTPStatus: http.StatusBadRequest}
		}
		m.User[lk] = values[0]
	}
	return m, nil
}

type objectResponseSource struct {
	Class           crypto.ObjectClass
	Meta, Decrypted map[string]string
	PlainSize       int64
	BackendETag     string
	Method          string
	VersionID       string
	Overrides       url.Values
}

func resolveCopyWriteMetadata(h http.Header, source objectResponseSource) (writeMetadata, *S3Error) {
	directive := strings.ToUpper(strings.TrimSpace(h.Get("x-amz-metadata-directive")))
	if directive == "" || directive == "COPY" {
		m := writeMetadata{User: make(map[string]string)}
		for k, v := range source.Meta {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") && !crypto.IsGatewayReservedKey(k) {
				m.User[strings.ToLower(k)] = v
			}
		}
		for k, v := range source.Decrypted {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") && !crypto.IsGatewayReservedKey(k) {
				m.User[strings.ToLower(k)] = v
			}
		}
		m.Standard, _ = objectmeta.Split(source.Meta)
		// Decrypted metadata represents the source's canonical plaintext view,
		// including standard headers restored from protected aliases.
		for _, name := range objectmeta.Names {
			if value := source.Decrypted[name]; value != "" {
				m.Standard = m.Standard.Set(name, value)
			}
		}
		if m.Standard.ContentType == "" {
			m.Standard.ContentType = "application/octet-stream"
		}
		return m, nil
	}
	if directive != "REPLACE" {
		return writeMetadata{}, &S3Error{Code: "InvalidArgument", Message: "Unknown metadata directive.", HTTPStatus: http.StatusBadRequest}
	}
	m, s3Err := parseWriteMetadata(h)
	if s3Err == nil && m.Standard.ContentType == "" {
		m.Standard.ContentType = "application/octet-stream"
	}
	return m, s3Err
}

func (m writeMetadata) engineInput(plainLen int64, haveLen bool) map[string]string {
	out := make(map[string]string, len(m.User)+len(objectmeta.Names)+1)
	for k, v := range m.User {
		out[k] = v
	}
	m.Standard.ApplyTo(out)
	if haveLen {
		out["Content-Length"] = strconv.FormatInt(plainLen, 10)
	}
	return out
}

type persistPlan struct {
	Metadata map[string]string
	Native   objectmeta.Standard
}

func buildPersistPlan(encMeta map[string]string, class crypto.ObjectClass, filterKeys []string) persistPlan {
	out := persistPlan{Metadata: make(map[string]string, len(encMeta))}
	for k, v := range encMeta {
		skip := false
		for _, f := range filterKeys {
			if strings.EqualFold(k, f) {
				skip = true
				break
			}
		}
		if !skip {
			out.Metadata[k] = v
		}
	}
	standard, remainder := objectmeta.Split(out.Metadata)
	out.Metadata = remainder
	if !class.Encrypted {
		out.Native = standard
	}
	for k := range out.Metadata {
		if strings.EqualFold(k, "content-length") || strings.EqualFold(k, "etag") || strings.EqualFold(k, "last-modified") {
			delete(out.Metadata, k)
		}
	}
	return out
}
