package api

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const contentLengthTestSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// Independent, deliberately narrow signing oracle for GH-356. The AWS Go SDK
// omits zero content-length from signing, and using createCanonicalRequest here
// would hide the regression. Sign the explicit header BEFORE simulating its loss.
func contentLengthSign(req *http.Request, presigned, signLength bool, at time.Time, body []byte) {
	timestamp := at.UTC().Format("20060102T150405Z")
	date := timestamp[:8]
	scope := date + "/us-east-1/s3/aws4_request"
	signed := "host;x-amz-content-sha256;x-amz-date"
	digest := sha256.Sum256(body)
	payload := hex.EncodeToString(digest[:])
	headers := "host:" + req.Host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + timestamp + "\n"
	if presigned {
		signed = "host"
		payload = "UNSIGNED-PAYLOAD"
		headers = "host:" + req.Host + "\n"
	} else {
		req.Header.Set("X-Amz-Date", timestamp)
		req.Header.Set("X-Amz-Content-Sha256", payload)
	}
	if signLength {
		signed = "content-length;" + signed
		headers = "content-length:" + req.Header.Get("Content-Length") + "\n" + headers
	}
	q := req.URL.Query()
	if presigned {
		q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		q.Set("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/"+scope)
		q.Set("X-Amz-Date", timestamp)
		q.Set("X-Amz-Expires", "900")
		q.Set("X-Amz-SignedHeaders", signed)
	}
	canonical := req.Method + "\n" + req.URL.EscapedPath() + "\n" + strings.ReplaceAll(q.Encode(), "+", "%20") + "\n" + headers + "\n" + signed + "\n" + payload
	hash := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(value))
		return h.Sum(nil)
	}
	key := mac([]byte("AWS4"+contentLengthTestSecret), date)
	key = mac(key, "us-east-1")
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	signature := hex.EncodeToString(mac(key, toSign))
	if presigned {
		q.Set("X-Amz-Signature", signature)
		req.URL.RawQuery = q.Encode()
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=%s, Signature=%s", scope, signed, signature))
	}
}

func TestSignedContentLength_CanonicalRequest(t *testing.T) {
	for _, tc := range []struct {
		name, explicit, want string
		length               int64
		signed               bool
	}{
		{"missing_zero", "", "content-length:0\n", 0, true},
		{"missing_positive", "", "content-length:37\n", 37, true},
		{"explicit_zero", "0", "content-length:0\n", 0, true},
		{"explicit_precedence", "0037", "content-length:0037\n", 99, true},
		{"case_insensitive_header", "37", "content-length:37\n", 99, true},
		{"unknown_length", "", "", -1, true},
		{"unsigned_zero", "", "", 0, false},
		{"unsigned_positive", "", "", 37, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "http://localhost/bucket/key", nil)
			req.ContentLength = tc.length
			if tc.explicit != "" {
				req.Header["cOnTeNt-LeNgTh"] = []string{tc.explicit}
			}
			before := req.Header.Clone()
			signed := []string{"host"}
			if tc.signed {
				signed = append(signed, "content-length")
			}
			canonical, err := createCanonicalRequest(req, false, signed)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" && strings.Contains(canonical, "content-length:") || tc.want != "" && !strings.Contains(canonical, tc.want) {
				t.Errorf("canonical request=%q, want length line %q", canonical, tc.want)
			}
			if !reflect.DeepEqual(req.Header, before) || req.ContentLength != tc.length {
				t.Fatal("canonicalization mutated the request")
			}
		})
	}
}

func TestSignedContentLength_ValidatorAndMiddleware(t *testing.T) {
	for _, presigned := range []bool{false, true} {
		mode := "header"
		if presigned {
			mode = "presigned"
		}
		for _, tc := range []struct {
			name, method, explicit string
			length                 int64
			strip, unsigned, bad   bool
			body                   []byte
		}{
			{name: "explicit_zero", method: "DELETE", explicit: "0"},
			{name: "recovered_delete", method: "DELETE", explicit: "0", strip: true},
			{name: "recovered_get", method: "GET", explicit: "0", strip: true},
			{name: "recovered_head", method: "HEAD", explicit: "0", strip: true},
			{name: "recovered_put", method: "PUT", explicit: "4", length: 4, strip: true, body: []byte("data")},
			{name: "unsigned_control", method: "DELETE", explicit: "0", strip: true, unsigned: true},
			{name: "wrong_known_length", method: "DELETE", explicit: "1", strip: true, bad: true},
			{name: "unknown_length", method: "DELETE", explicit: "0", length: -1, strip: true, bad: true},
			{name: "negative_not_a_wire_length", method: "DELETE", explicit: "-1", length: -1, strip: true, bad: true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(tc.method, "http://localhost/bucket/key", bytes.NewReader(tc.body))
				req.Header.Set("Content-Length", tc.explicit)
				contentLengthSign(req, presigned, !tc.unsigned, time.Now().UTC(), tc.body)
				req.ContentLength = tc.length
				if tc.length < 0 {
					req.TransferEncoding = []string{"chunked"}
				}
				if tc.strip {
					req.Header.Del("Content-Length")
				}
				before := req.Header.Clone()
				ctx, err := ValidateSignatureV4(req, contentLengthTestSecret, time.Minute)
				if ctx != nil {
					ctx.Close()
				}
				if tc.bad {
					if !errors.Is(err, ErrSignatureMismatch) || ctx != nil {
						t.Errorf("context=%v error=%v, want signature mismatch without context", ctx, err)
					}
				} else if err != nil {
					t.Errorf("independently signed request rejected: %v", err)
				}
				if !reflect.DeepEqual(before, req.Header) {
					t.Fatal("signature validation mutated headers")
				}
				logger := logrus.New()
				logger.SetOutput(io.Discard)
				auditLog := audit.NewLogger(10, presignedTimeAuditWriter{})
				called := false
				handler := AuthMiddleware(testCredentialStore(), time.Minute, logger, auditLog, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					got, readErr := io.ReadAll(r.Body)
					if readErr != nil || !bytes.Equal(got, tc.body) {
						t.Errorf("replayed body=%q error=%v", got, readErr)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				want := http.StatusNoContent
				if tc.bad {
					want = http.StatusForbidden
				}
				if rec.Code != want || called == tc.bad {
					t.Errorf("status=%d next=%v, want status=%d next=%v; body=%s", rec.Code, called, want, !tc.bad, rec.Body.String())
				}
				if tc.bad {
					contentLengthAssertError(t, rec.Body.Bytes(), req.URL.Path)
					if events := auditLog.GetEvents(); len(events) != 1 || events[0].EventType != audit.EventTypeAuthFailure || events[0].Success {
						t.Errorf("want one failed-auth event, got %+v", events)
					}
				} else if events := auditLog.GetEvents(); len(events) != 0 {
					t.Errorf("successful authentication emitted failure events: %+v", events)
				}
			})
		}
	}
}

func contentLengthAssertError(t *testing.T, body []byte, path string) {
	t.Helper()
	var response struct{ Code, Message, Resource string }
	if err := xml.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "SignatureDoesNotMatch" || response.Resource != path || response.Message != "The request signature we calculated does not match the signature you provided. Check your key and signing method." {
		t.Errorf("unexpected auth error: %+v", response)
	}
	if bytes.Contains(body, []byte(contentLengthTestSecret)) {
		t.Error("auth error leaked signing material")
	}
}

// A real frontend proxy is essential here: Go's client transport, not a
// manually edited Header map, must remove the signed Content-Length: 0.
func TestSignedContentLength_ReverseProxyDelete(t *testing.T) {
	for _, tc := range []struct {
		name             string
		proxy, presigned bool
		unsigned, bad    bool
	}{
		{name: "direct_header"},
		{name: "proxy_header", proxy: true},
		{name: "direct_presigned", presigned: true},
		{name: "proxy_presigned", proxy: true, presigned: true},
		{name: "proxy_unsigned_control", proxy: true, unsigned: true},
		{name: "proxy_wrong_length", proxy: true, bad: true},
		{name: "proxy_presigned_wrong_length", proxy: true, presigned: true, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/key"] = []byte("keep until authenticated deletion")
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			h := NewHandler(backend, crypto.PassthroughEngine{}, logger, getTestMetrics())
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			auth := AuthMiddleware(testCredentialStore(), time.Minute, logger, nil, false)(AuthorizationMiddleware("", nil)(router))
			var seen atomic.Int64
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				wantHeader := "0"
				if tc.proxy {
					wantHeader = ""
				}
				if r.Header.Get("Content-Length") != wantHeader || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
					t.Errorf("gateway wire header=%q length=%d encoding=%v", r.Header.Get("Content-Length"), r.ContentLength, r.TransferEncoding)
				}
				auth.ServeHTTP(w, r)
			}))
			defer gateway.Close()
			endpoint := gateway.URL
			if tc.proxy {
				target, err := url.Parse(gateway.URL)
				if err != nil {
					t.Fatal(err)
				}
				transport := http.DefaultTransport.(*http.Transport).Clone()
				defer transport.CloseIdleConnections()
				proxy := httputil.NewSingleHostReverseProxy(target)
				proxy.Transport = transport
				frontend := httptest.NewServer(proxy)
				defer frontend.Close()
				endpoint = frontend.URL
			}
			req := httptest.NewRequest(http.MethodDelete, "http://s3.example.test/bucket/key", nil)
			req.Header.Set("Content-Length", "0")
			if tc.bad {
				req.Header.Set("Content-Length", "1")
			}
			contentLengthSign(req, tc.presigned, !tc.unsigned, time.Now().UTC(), nil)
			// Write the original zero-length header explicitly; Request.Write would
			// itself omit it for DELETE and destroy the direct positive control.
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(endpoint, "http://"), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Length", "0")
			if _, err := fmt.Fprintf(conn, "DELETE %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host); err != nil {
				t.Fatal(err)
			}
			if err := req.Header.Write(conn); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := http.StatusNoContent
			if tc.bad {
				want = http.StatusForbidden
			}
			if resp.StatusCode != want || seen.Load() != 1 {
				t.Errorf("status=%d gateway calls=%d, want status=%d; body=%s", resp.StatusCode, seen.Load(), want, body)
			}
			if tc.bad {
				contentLengthAssertError(t, body, "/bucket/key")
				if backend.headObjectCallCount != 0 || backend.deleteObjectCallCount != 0 || backend.objects["bucket/key"] == nil {
					t.Fatal("rejected signature accessed or mutated backend")
				}
			} else if backend.deleteObjectCallCount != 1 || backend.objects["bucket/key"] != nil {
				t.Errorf("authenticated DELETE did not delete exactly once: calls=%d", backend.deleteObjectCallCount)
			}
		})
	}
}
