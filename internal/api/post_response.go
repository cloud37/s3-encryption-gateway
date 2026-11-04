package api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

const postResponseNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type postResponse struct {
	XMLName  xml.Name `xml:"PostResponse"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// parsePostSuccess interprets already-validated scalar fields without changing
// their submitted representation. Invalid status values and redirect URLs use
// the S3 default status path; having both redirect aliases is ambiguous.
func parsePostSuccess(fields map[string]string) (int, *url.URL, error) {
	status := http.StatusNoContent
	if raw, present := postFormField(fields, "success_action_status", ""); present {
		if raw == "200" || raw == "201" || raw == "204" {
			parsed, _ := strconv.Atoi(raw)
			status = parsed
		}
	}
	redirect, hasSuccess := postFormField(fields, "success_action_redirect", "")
	legacy, hasLegacy := postFormField(fields, "redirect", "")
	if hasSuccess && hasLegacy {
		return 0, nil, ErrPostInvalidOption
	}
	raw := redirect
	if hasLegacy {
		raw = legacy
	}
	if raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) || hasURLControl(raw) {
		return status, nil, nil
	}
	target, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || !validPostRedirectURL(target) {
		return status, nil, nil
	}
	if _, queryErr := url.ParseQuery(target.RawQuery); queryErr != nil {
		return status, nil, nil
	}
	clone := *target
	return status, &clone, nil
}

func validPostRedirectURL(target *url.URL) bool {
	if target == nil || target.Opaque != "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || hasURLControl(target.String()) {
		return false
	}
	_, err := parsePostAuthority(target.Host)
	if err != nil {
		return false
	}
	_, err = url.ParseQuery(target.RawQuery)
	return err == nil
}

func postObjectLocation(r *http.Request, bucket, key string, secure bool) (string, error) {
	if r == nil || r.URL == nil {
		return "", ErrPostInvalidOption
	}
	if err := (crypto.ObjectContext{Bucket: bucket, Key: key}).Validate(); err != nil || !utf8.ValidString(bucket) || !utf8.ValidString(key) || !validXMLText(bucket) || !validXMLText(key) {
		return "", ErrPostInvalidOption
	}
	authority, err := parsePostAuthority(r.Host)
	if err != nil {
		return "", ErrPostInvalidOption
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	escapedKey := escapePostPathComponent(key)
	escapedBucket := url.PathEscape(bucket)
	path := "/" + escapedBucket + "/" + escapedKey
	location := scheme + "://" + authority + path
	return location, nil
}

func escapePostPathComponent(value string) string {
	parts := strings.Split(value, "/")
	for index := range parts {
		parts[index] = strings.ReplaceAll(url.PathEscape(parts[index]), ".", "%2E")
	}
	return strings.Join(parts, "/")
}

func parsePostAuthority(authority string) (string, error) {
	if authority == "" || hasURLControl(authority) || strings.ContainsAny(authority, "/\\?#@ \t") {
		return "", errors.New("invalid authority")
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Host != authority || parsed.User != nil || parsed.Hostname() == "" {
		return "", errors.New("invalid authority")
	}
	if strings.HasPrefix(authority, "[") {
		ip := parsed.Hostname()
		if net.ParseIP(ip) == nil {
			return "", errors.New("invalid IPv6 authority")
		}
	} else if strings.Count(authority, ":") > 1 {
		return "", errors.New("IPv6 authority must be bracketed")
	} else if !validPostDNSOrIPv4(parsed.Hostname()) {
		return "", errors.New("invalid host name")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return "", errors.New("invalid authority port")
		}
	}
	return authority, nil
}

func hasURLControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validPostDNSOrIPv4(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validXMLText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == 0x9 || r == 0xa || r == 0xd || (r >= 0x20 && r <= 0xd7ff) || (r >= 0xe000 && r <= 0xfffd) || (r >= 0x10000 && r <= 0x10ffff) {
			continue
		}
		return false
	}
	return true
}

func postRedirectLocation(target *url.URL, bucket, key, etag string) string {
	if target == nil {
		return ""
	}
	clone := *target
	values, err := url.ParseQuery(clone.RawQuery)
	if err != nil {
		return ""
	}
	values.Set("bucket", bucket)
	values.Set("key", key)
	values.Set("etag", etag)
	clone.RawQuery = values.Encode()
	return clone.String()
}

func (h *Handler) writePostSuccess(w http.ResponseWriter, r *http.Request, upload *postUpload, result objectWriteResult, checksums map[string]string) error {
	if h == nil || w == nil || r == nil || upload == nil {
		return ErrPostInvalidOption
	}
	if upload.successStatus != http.StatusOK && upload.successStatus != http.StatusCreated && upload.successStatus != http.StatusNoContent {
		return ErrPostInvalidOption
	}
	secure := r.TLS != nil || h.trustedIPExtractor != nil && !h.trustedIPExtractorInvalid && h.trustedIPExtractor.IsHTTPSRequest(r)
	location, err := postObjectLocation(r, upload.bucket, upload.key, secure)
	if err != nil {
		return err
	}
	effectiveETag := effectiveObjectWriteETag(result)
	headers := projectObjectWriteHeaders(result, checksums)
	if upload.redirect != nil {
		if !validPostRedirectURL(upload.redirect) {
			return ErrPostInvalidOption
		}
		redirectLocation := postRedirectLocation(upload.redirect, upload.bucket, upload.key, effectiveETag)
		if redirectLocation == "" {
			return ErrPostInvalidOption
		}
		headers = projectPostResponseHeaders(result, checksums, "", redirectLocation)
		if err := validatePostResponseHeaders(headers); err != nil {
			return err
		}
		writeObjectHeaders(w, headers)
		w.WriteHeader(http.StatusSeeOther)
		return nil
	}
	if upload.successStatus == http.StatusCreated {
		response := postResponse{XMLNS: postResponseNamespace, Location: location, Bucket: upload.bucket, Key: upload.key, ETag: quoteETag(effectiveETag)}
		if !validXMLText(response.Location) || !validXMLText(response.Bucket) || !validXMLText(response.Key) || !validXMLText(response.ETag) {
			return ErrPostInvalidOption
		}
		body, marshalErr := xml.Marshal(response)
		if marshalErr != nil {
			return ErrPostInvalidOption
		}
		body = append([]byte(xml.Header), body...)
		headers = projectPostResponseHeaders(result, checksums, "application/xml", "")
		if err := validatePostResponseHeaders(headers); err != nil {
			return err
		}
		writeObjectHeaders(w, headers)
		w.WriteHeader(http.StatusCreated)
		if err := writePostResponseBody(w, body); err != nil {
			return err
		}
		return nil
	}
	if err := validatePostResponseHeaders(headers); err != nil {
		return err
	}
	writeObjectHeaders(w, headers)
	w.WriteHeader(upload.successStatus)
	return nil
}

func validatePostResponseHeaders(headers http.Header) error {
	for name, values := range headers {
		if name == "Content-Length" || name == "Content-Range" {
			return fmt.Errorf("%w: object length is not a POST response length", ErrPostInvalidOption)
		}
		for _, value := range values {
			if hasURLControl(value) || !utf8.ValidString(value) {
				return ErrPostInvalidOption
			}
		}
	}
	return nil
}

func writePostResponseBody(w http.ResponseWriter, body []byte) error {
	n, err := w.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}
