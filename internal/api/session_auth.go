package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid session token")
	ErrExpiredToken = errors.New("expired session token")
)

// validateSessionCredentialAt validates an operator-configured identity, not an
// STS assertion. Deadline is exclusive; clock skew never extends its lifetime.
func validateSessionCredentialAt(c Credential, supplied string, now time.Time) error {
	if c.SessionToken == "" {
		if supplied != "" || c.ExpiresAt != nil {
			return ErrInvalidToken
		}
		return nil
	}
	if c.ExpiresAt == nil {
		return ErrInvalidToken
	}
	if !now.Before(*c.ExpiresAt) {
		return ErrExpiredToken
	}
	want, got := sha256.Sum256([]byte(c.SessionToken)), sha256.Sum256([]byte(supplied))
	if subtle.ConstantTimeCompare(want[:], got[:])&subtle.ConstantTimeEq(int32(len(c.SessionToken)), int32(len(supplied))) != 1 || supplied == "" {
		return ErrInvalidToken
	}
	return nil
}

// sessionTokenFromRequest reads only ordinary SigV4 transports. POST policy
// validation supplies its already duplicate-checked scalar token directly to
// validateSessionCredentialAt and must require an exact policy condition.
// No body parsing or mutation of signed bytes is allowed here.
func sessionTokenFromRequest(r *http.Request) (string, error) {
	if r == nil || r.URL == nil {
		return "", ErrInvalidToken
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", ErrInvalidToken
	}
	var headerValues, queryValues []string
	var headerPresent, queryPresent bool
	for name, values := range r.Header {
		if strings.EqualFold(name, "x-amz-security-token") {
			headerPresent = true
			headerValues = append(headerValues, values...)
		}
	}
	for name, values := range query {
		if strings.EqualFold(name, "x-amz-security-token") {
			// SigV4 canonical query selection is case-sensitive. Do not accept
			// a differently cased alias as the canonical session parameter.
			if name != "X-Amz-Security-Token" {
				return "", ErrInvalidToken
			}
			queryPresent = true
			queryValues = append(queryValues, values...)
		}
	}
	if headerPresent && queryPresent {
		return "", ErrInvalidToken
	}
	if !headerPresent && !queryPresent {
		return "", nil
	}
	presigned := query.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
	values := headerValues
	if presigned {
		if !queryPresent || r.Header.Get("Authorization") != "" {
			return "", ErrInvalidToken
		}
		values = queryValues // the validated canonical query signs every token byte
	} else {
		if !headerPresent || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			return "", ErrInvalidToken
		}
		signed := false
		signedHeaderLists := 0
		for _, component := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ",") {
			pair := strings.SplitN(strings.TrimSpace(component), "=", 2)
			if len(pair) == 2 && pair[0] == "SignedHeaders" {
				signedHeaderLists++
				for _, name := range strings.Split(pair[1], ";") {
					if name == "x-amz-security-token" {
						signed = true
					}
				}
			}
		}
		if !signed || signedHeaderLists != 1 {
			return "", ErrInvalidToken
		}
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 16*1024 || strings.ContainsAny(values[0], "\x00\r\n") {
		return "", ErrInvalidToken
	}
	return values[0], nil
}
