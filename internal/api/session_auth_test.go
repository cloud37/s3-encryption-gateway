package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGH353SessionAuth_TokenAndDeadline(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 123, time.UTC)
	deadline := now.Add(time.Nanosecond)
	c := Credential{SessionToken: "opaque-token", ExpiresAt: &deadline}
	for _, tc := range []struct {
		name, token string
		at          time.Time
		c           Credential
		want        error
	}{
		{"before", "opaque-token", now, c, nil},
		{"at", "opaque-token", deadline, c, ErrExpiredToken},
		{"after", "opaque-token", deadline.Add(time.Nanosecond), c, ErrExpiredToken},
		{"missing", "", now, c, ErrInvalidToken},
		{"wrong_same_length", "opaque-tokeX", now, c, ErrInvalidToken},
		{"wrong_length", "opaque-token-more", now, c, ErrInvalidToken},
		{"static", "", now, Credential{}, nil},
		{"static_extra", "opaque-token", now, Credential{}, ErrInvalidToken},
		{"invalid_no_deadline", "opaque-token", now, Credential{SessionToken: "opaque-token"}, ErrInvalidToken},
		{"invalid_static_deadline", "", now, Credential{ExpiresAt: &deadline}, ErrInvalidToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, errors.Is(validateSessionCredentialAt(tc.c, tc.token, tc.at), tc.want))
		})
	}
	// POST passes the same bounded scalar directly; exact policy coverage is
	// enforced by Phase C, not by an ordinary-request body parser.
	require.NoError(t, validateSessionCredentialAt(c, map[string]string{"x-amz-security-token": "opaque-token"}["x-amz-security-token"], now))
}

func gh353SignedSessionRequest(t *testing.T, presigned bool, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "http://localhost/bucket/key", strings.NewReader("must-not-spool-on-session-denial"))
	digest := sha256.Sum256([]byte("must-not-spool-on-session-denial"))
	r.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
	c := aws.Credentials{AccessKeyID: "session", SecretAccessKey: "session-secret", SessionToken: token}
	if presigned {
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		q := r.URL.Query()
		q.Set("X-Amz-Expires", "900")
		r.URL.RawQuery = q.Encode()
		raw, headers, err := v4.NewSigner().PresignHTTP(t.Context(), c, r, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", time.Now().UTC())
		require.NoError(t, err)
		r.URL, err = r.URL.Parse(raw)
		require.NoError(t, err)
		for name, values := range headers {
			r.Header[name] = values
		}
	} else {
		require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), c, r, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", time.Now().UTC()))
	}
	return r
}

type gh353UnreadBody struct{ reads int }

func (b *gh353UnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*gh353UnreadBody) Close() error               { return nil }

func TestGH353SessionAuth_SignedTransports(t *testing.T) {
	for _, presigned := range []bool{false, true} {
		for _, tc := range []struct {
			name, supplied, configured string
			expired                    bool
			mutate                     func(*http.Request)
			code                       string
		}{
			{name: "valid", supplied: "token", configured: "token"},
			{name: "static_valid"},
			{name: "missing", configured: "token", code: "InvalidToken"},
			{name: "unsigned_token", configured: "token", mutate: func(r *http.Request) {
				if r.URL.Query().Get("X-Amz-Algorithm") == "" {
					r.Header.Set("X-Amz-Security-Token", "token")
				}
			}, code: "InvalidToken"},
			{name: "wrong", supplied: "wrong", configured: "token", code: "InvalidToken"},
			{name: "static_extra", supplied: "token", code: "InvalidToken"},
			{name: "expired", supplied: "token", configured: "token", expired: true, code: "ExpiredToken"},
			{name: "duplicate", supplied: "token", configured: "token", mutate: func(r *http.Request) {
				if presigned {
					q := r.URL.Query()
					q.Add("X-Amz-Security-Token", "token")
					q.Del("X-Amz-Signature")
					r.URL.RawQuery = q.Encode()
					raw, _, err := v4.NewSigner().PresignHTTP(t.Context(), aws.Credentials{AccessKeyID: "session", SecretAccessKey: "session-secret"}, r, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", time.Now().UTC())
					require.NoError(t, err)
					r.URL, err = r.URL.Parse(raw)
					require.NoError(t, err)
				} else {
					r.Header.Add("X-Amz-Security-Token", "token")
					require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "session", SecretAccessKey: "session-secret"}, r, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", time.Now().UTC()))
				}
			}, code: "InvalidToken"},
			{name: "mixed", supplied: "token", configured: "token", mutate: func(r *http.Request) {
				if presigned {
					r.Header.Set("X-Amz-Security-Token", "token")
				} else {
					q := r.URL.Query()
					q.Set("X-Amz-Security-Token", "token")
					r.URL.RawQuery = q.Encode()
					require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "session", SecretAccessKey: "session-secret", SessionToken: "token"}, r, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", time.Now().UTC()))
				}
			}, code: "InvalidToken"},
		} {
			t.Run(tc.name+map[bool]string{true: "_query", false: "_header"}[presigned], func(t *testing.T) {
				r := gh353SignedSessionRequest(t, presigned, tc.supplied)
				if tc.mutate != nil {
					tc.mutate(r)
				}
				signing, sigErr := ValidateSignatureV4(r, "session-secret", time.Minute*5)
				require.NoError(t, sigErr, "session rejection fixture must have a valid ordinary signature")
				if signing != nil {
					if tc.code != "" && !presigned {
						assert.True(t, signing.verifyPayload, "rejection must precede otherwise-required body spool")
					}
					signing.Close()
				}
				deadline := time.Now().UTC().Add(time.Hour)
				if tc.expired {
					deadline = time.Now().UTC().Add(-time.Hour)
				}
				cred := config.GatewayCredential{AccessKey: "session", SecretKey: "session-secret", SessionToken: tc.configured}
				if tc.configured != "" {
					cred.ExpiresAt = &deadline
				}
				store, err := NewStaticCredentialStore([]config.GatewayCredential{cred})
				require.NoError(t, err)
				body := &gh353UnreadBody{}
				if tc.code != "" {
					r.Body = body
				}
				logger := logrus.New()
				logger.SetOutput(io.Discard)
				auditLog := audit.NewLogger(10, presignedTimeAuditWriter{})
				called := false
				h := AuthMiddleware(store, time.Minute*5, logger, auditLog, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					principal, ok := r.Context().Value(credentialKey).(Credential)
					require.True(t, ok)
					assert.Equal(t, tc.configured, principal.SessionToken)
					w.WriteHeader(200)
				}))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				assert.Zero(t, body.reads)
				if tc.code == "" {
					assert.Equal(t, 200, rec.Code)
					assert.True(t, called)
					assert.Empty(t, auditLog.GetEvents())
					return
				}
				assert.False(t, called)
				assert.Equal(t, 403, rec.Code)
				var response struct{ Code, Message, Resource string }
				require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &response))
				assert.Equal(t, tc.code, response.Code)
				assert.Equal(t, "/bucket/key", response.Resource)
				assert.Equal(t, map[string]string{"InvalidToken": "The provided token is invalid.", "ExpiredToken": "The provided token has expired."}[tc.code], response.Message)
				assert.Len(t, auditLog.GetEvents(), 1)
			})
		}
	}
	// Helpers reject ambiguity before interpreting values. Preserve all bytes.
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"duplicate_header", func(r *http.Request) { r.Header.Add("X-Amz-Security-Token", "token") }},
		{"case_alias_header", func(r *http.Request) { r.Header["x-amz-security-token"] = []string{"token"} }},
		{"unsigned_header", func(r *http.Request) {
			r.Header.Set("Authorization", strings.ReplaceAll(r.Header.Get("Authorization"), ";x-amz-security-token", ""))
		}},
		{"duplicate_signed_header_lists", func(r *http.Request) {
			r.Header.Set("Authorization", r.Header.Get("Authorization")+", SignedHeaders=host;x-amz-security-token")
		}},
		{"empty_header", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "") }},
		{"header_on_query", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
			r.URL.RawQuery = q.Encode()
		}},
		{"query_on_header", func(r *http.Request) {
			r.Header.Del("X-Amz-Security-Token")
			q := r.URL.Query()
			q.Set("X-Amz-Security-Token", "token")
			r.URL.RawQuery = q.Encode()
		}},
		{"duplicate_query", func(r *http.Request) {
			r.Header.Del("X-Amz-Security-Token")
			q := r.URL.Query()
			q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
			q["X-Amz-Security-Token"] = []string{"token", "token"}
			r.URL.RawQuery = q.Encode()
			r.Header.Del("Authorization")
		}},
		{"case_alias_query", func(r *http.Request) { r.URL.RawQuery = "x-amz-security-token=token" }},
		{"malformed_query", func(r *http.Request) { r.URL.RawQuery = "%bad=%GG" }},
		{"nul", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "token\x00") }},
		{"crlf", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "token\r\n") }},
		{"oversize", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", strings.Repeat("x", 16*1024+1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gh353SignedSessionRequest(t, false, "token")
			tc.mutate(r)
			beforeHeader, beforeQuery := r.Header.Clone(), r.URL.RawQuery
			_, err := sessionTokenFromRequest(r)
			assert.ErrorIs(t, err, ErrInvalidToken)
			assert.Equal(t, beforeHeader, r.Header)
			assert.Equal(t, beforeQuery, r.URL.RawQuery)
		})
	}
	_, err := sessionTokenFromRequest(nil)
	assert.ErrorIs(t, err, ErrInvalidToken)
	_, err = sessionTokenFromRequest(&http.Request{})
	assert.ErrorIs(t, err, ErrInvalidToken)
	// Valid ordinary signature with an unsigned added token must still fail.
	r := gh353SignedSessionRequest(t, false, "")
	r.Header.Set("X-Amz-Security-Token", "token")
	ctx, err := ValidateSignatureV4(r, "session-secret", time.Minute*5)
	require.NoError(t, err)
	if ctx != nil {
		ctx.Close()
	}
	_, err = sessionTokenFromRequest(r)
	assert.ErrorIs(t, err, ErrInvalidToken)
	// Session SigV2 is denied even when the operator enables legacy static auth.
	deadline := time.Now().UTC().Add(time.Hour)
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "session", SecretKey: "secret", SessionToken: "token", ExpiresAt: &deadline}})
	require.NoError(t, err)
	r = httptest.NewRequest("GET", "http://localhost/bucket/key", nil)
	r.Header.Set("Authorization", "AWS session:any-signature")
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	rec := httptest.NewRecorder()
	AuthMiddleware(store, time.Minute*5, logger, nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("session SigV2 reached downstream") })).ServeHTTP(rec, r)
	assert.Equal(t, 403, rec.Code)
	assert.Contains(t, rec.Body.String(), "<Code>InvalidToken</Code>")
}

func TestGH353CredentialStore_SessionSnapshotIsolation(t *testing.T) {
	deadline := time.Now().UTC().Add(time.Hour)
	source := []config.GatewayCredential{{AccessKey: "key", SecretKey: "secret", SessionToken: "old", ExpiresAt: &deadline, Buckets: []string{"bucket"}}}
	store, err := NewStaticCredentialStore(source)
	require.NoError(t, err)
	initial := deadline
	deadline = deadline.Add(time.Hour)
	source[0].SessionToken = "caller-mutated"
	source[0].Buckets[0] = "other"
	old, err := store.Lookup("key")
	require.NoError(t, err)
	assert.Equal(t, initial, *old.ExpiresAt)
	assert.Equal(t, "old", old.SessionToken)
	assert.True(t, old.AllowsBucket("bucket"))
	*old.ExpiresAt = initial.Add(time.Hour)
	lookup, err := store.Lookup("key")
	require.NoError(t, err)
	assert.Equal(t, initial, *lookup.ExpiresAt)
	nextDeadline := initial.Add(time.Hour * 3)
	require.NoError(t, store.Replace([]config.GatewayCredential{{AccessKey: "key", SecretKey: "new-secret", SessionToken: "new", ExpiresAt: &nextDeadline}}))
	current, err := store.Lookup("key")
	require.NoError(t, err)
	assert.Equal(t, "new", current.SessionToken)
	assert.Equal(t, "old", old.SessionToken)
	assert.Equal(t, "secret", old.SecretKey)
	for _, invalid := range [][]config.GatewayCredential{nil, {{AccessKey: "key", SecretKey: "secret", SessionToken: "no-deadline"}}, {{AccessKey: "key", SecretKey: "secret"}, {AccessKey: "bad"}}} {
		require.Error(t, store.Replace(invalid))
		retained, err := store.Lookup("key")
		require.NoError(t, err)
		assert.Equal(t, current, retained)
	}
	_, err = (&StaticCredentialStore{}).Lookup("unknown")
	assert.ErrorIs(t, err, ErrUnknownAccessKey)
	_, err = store.Lookup("unknown")
	assert.ErrorIs(t, err, ErrUnknownAccessKey)
}
