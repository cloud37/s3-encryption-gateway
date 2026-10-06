package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const corsModePassthrough = "passthrough"
const corsModeGateway = "gateway"

// ValidateCORSOriginPattern validates an S3 origin pattern. A single '*' is
// permitted as a same-origin-string wildcard, and standalone '*' is allowed.
func ValidateCORSOriginPattern(pattern string) error {
	if pattern == "*" {
		return nil
	}
	if strings.EqualFold(pattern, "null") || pattern == "" || strings.ContainsAny(pattern, "?#") || strings.Count(pattern, "*") > 1 {
		return fmt.Errorf("invalid CORS origin pattern")
	}
	for _, r := range pattern {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("invalid CORS origin pattern")
		}
	}
	scheme, authority, ok := strings.Cut(pattern, "://")
	if !ok || (scheme != "http" && scheme != "https") {
		return fmt.Errorf("origin must be an http or https origin without path, query, or fragment")
	}
	if authority == "" || strings.ContainsAny(authority, "/\\@\"'<>%") {
		return fmt.Errorf("origin has invalid authority")
	}
	return validateCORSOriginAuthority(authority)
}

func validateCORSOriginAuthority(authority string) error {
	var host, port string
	portPresent := false
	if strings.HasPrefix(authority, "[") {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket <= 1 || strings.ContainsAny(authority[closeBracket+1:], "[]") {
			return fmt.Errorf("origin has invalid IP literal authority")
		}
		host = authority[1:closeBracket]
		ip := net.ParseIP(host)
		if ip == nil || !strings.Contains(host, ":") {
			return fmt.Errorf("origin has invalid IP literal")
		}
		suffix := authority[closeBracket+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return fmt.Errorf("origin has invalid IP literal authority")
			}
			portPresent, port = true, suffix[1:]
		}
	} else {
		if strings.ContainsAny(authority, "[]") {
			return fmt.Errorf("origin has invalid hostname authority")
		}
		host = authority
		if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
			if strings.Contains(host[:colon], ":") {
				return fmt.Errorf("IPv6 origins must use a bracketed IP literal")
			}
			portPresent, port = true, host[colon+1:]
			host = host[:colon]
		}
		wildcardHost := strings.Replace(host, "*", "x", 1)
		if !validCORSOriginDNSName(wildcardHost) {
			return fmt.Errorf("origin has invalid hostname")
		}
		if strings.Trim(wildcardHost, "0123456789.") == "" && net.ParseIP(wildcardHost) == nil {
			return fmt.Errorf("origin has invalid IPv4 literal")
		}
	}
	if host == "" {
		return fmt.Errorf("origin hostname is empty")
	}
	if portPresent {
		if port == "" {
			return fmt.Errorf("origin has invalid port")
		}
		for _, digit := range port {
			if digit < '0' || digit > '9' {
				return fmt.Errorf("origin has invalid port")
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("origin has invalid port")
		}
	}
	return nil
}

func validCORSOriginDNSName(hostname string) bool {
	if hostname == "" || len(hostname) > 254 {
		return false
	}
	name := strings.TrimSuffix(hostname, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !isCORSOriginAlphaNumeric(label[0]) || !isCORSOriginAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isCORSOriginAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isCORSOriginAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

// ValidateCORSHeaderPattern validates an HTTP field-name pattern with at most
// one wildcard. Wildcards match zero or more token characters at evaluation.
func ValidateCORSHeaderPattern(pattern string) error {
	if pattern == "" || strings.Count(pattern, "*") > 1 {
		return fmt.Errorf("invalid CORS header pattern")
	}
	return validateCORSHeaderChars(strings.ReplaceAll(pattern, "*", ""))
}

// ValidateCORSFieldName validates a concrete HTTP field-name token.
func ValidateCORSFieldName(name string) error {
	if name == "" || strings.Contains(name, "*") {
		return fmt.Errorf("invalid CORS field name")
	}
	return validateCORSHeaderChars(name)
}

func validateCORSHeaderChars(value string) error {
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'+-.^_`|~", c) {
			continue
		}
		return fmt.Errorf("invalid HTTP field-name character")
	}
	return nil
}

// EffectiveCORSMode resolves the backward-compatible zero value.
func EffectiveCORSMode(mode string) string {
	if mode == "" {
		return corsModePassthrough
	}
	return mode
}

// Validate checks mode, fallback, and shared-Valkey requirements.
func (c CORSConfig) Validate(hasValkey bool) error {
	mode := EffectiveCORSMode(c.Mode)
	if mode != corsModePassthrough && mode != corsModeGateway {
		return fmt.Errorf("cors.mode must be passthrough or gateway")
	}
	f := c.Fallback
	populated := len(f.AllowedOrigins)+len(f.AllowedMethods)+len(f.AllowedHeaders)+len(f.ExposeHeaders) > 0 || f.MaxAgeSeconds != 0
	if mode == corsModePassthrough {
		if c.AllowCredentials || populated {
			return fmt.Errorf("cors fallback and allow_credentials require gateway mode")
		}
		return nil
	}
	if !hasValkey {
		return fmt.Errorf("cors.mode gateway requires multipart_state.valkey.addr")
	}
	if f.MaxAgeSeconds < 0 {
		return fmt.Errorf("cors.fallback.max_age_seconds must be nonnegative")
	}
	if populated && (len(f.AllowedOrigins) == 0 || len(f.AllowedMethods) == 0) {
		return fmt.Errorf("cors fallback requires both allowed_origins and allowed_methods")
	}
	for _, origin := range f.AllowedOrigins {
		if err := ValidateCORSOriginPattern(origin); err != nil {
			return fmt.Errorf("invalid cors.fallback.allowed_origins entry %q: %w", origin, err)
		}
	}
	for _, method := range f.AllowedMethods {
		if !validCORSMethod(method) {
			return fmt.Errorf("invalid cors.fallback.allowed_methods entry %q", method)
		}
	}
	for _, header := range f.AllowedHeaders {
		if err := ValidateCORSHeaderPattern(header); err != nil {
			return fmt.Errorf("invalid cors.fallback.allowed_headers entry %q: %w", header, err)
		}
	}
	for _, header := range f.ExposeHeaders {
		if err := ValidateCORSFieldName(header); err != nil {
			return fmt.Errorf("invalid cors.fallback.expose_headers entry %q: %w", header, err)
		}
	}
	return nil
}

func validCORSMethod(method string) bool {
	switch method {
	case "GET", "PUT", "POST", "DELETE", "HEAD":
		return true
	default:
		return false
	}
}
