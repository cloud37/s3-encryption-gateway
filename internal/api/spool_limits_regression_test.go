package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestVerifyAndSpoolV4Payload_RequestAndAggregateLimitsCleanup(t *testing.T) {
	dir := t.TempDir()
	m := NewSpoolManager(4, dir).(*spoolManager)
	body := []byte("payload")
	sum := sha256.Sum256(body)
	r := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	s := &V4SigningContext{verifyPayload: true, expectedPayloadHash: sum}
	if _, err := verifyAndSpoolV4Payload(r, s, m, int64(4)); !errors.Is(err, ErrSpoolRequestLimit) {
		t.Fatalf("err=%v", err)
	}
	if m.CurrentBytes() != 0 {
		t.Fatalf("leaked bytes=%d", m.CurrentBytes())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("spool files leaked: %v", entries)
	}
}

func TestVerifyAndSpoolAWSBody_RequestAndAggregateLimitsCleanup(t *testing.T) {
	dir := t.TempDir()
	m := NewSpoolManager(2, dir).(*spoolManager)
	r := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", bytes.NewBufferString("3\r\nabc\r\n0\r\n\r\n"))
	r.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	r.Header.Set("content-encoding", "aws-chunked")
	r.Header.Set("x-amz-decoded-content-length", "3")
	if _, err := verifyAndSpoolAWSBody(r, nil, m, int64(3)); !errors.Is(err, ErrSpoolCapacity) {
		t.Fatalf("err=%v", err)
	}
	if m.CurrentBytes() != 0 {
		t.Fatalf("leaked bytes=%d", m.CurrentBytes())
	}
}

func TestAuthMiddleware_SpoolLimitRejectedBeforeNext(t *testing.T) {
	t.Run("upload-part-request-limit", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), 8)
		req := signedConcreteRequest(t, body)
		req.URL.RawQuery = "partNumber=1&uploadId=u"
		resignV4Request(t, req, fmt.Sprintf("%x", sha256.Sum256(body)))
		req.ContentLength = int64(len(body))
		read := false
		req.Body = trackingBody{Reader: bytes.NewReader(body), read: &read}
		m := NewSpoolManager(64).(*spoolManager)
		next := false
		h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 64, Part: 4})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "EntityTooLarge") || next || read || m.CurrentBytes() != 0 {
			t.Fatalf("status=%d next=%v read=%v bytes=%d body=%s", rec.Code, next, read, m.CurrentBytes(), rec.Body.String())
		}
	})
	t.Run("aggregate-limit", func(t *testing.T) {
		m := NewSpoolManager(4).(*spoolManager)
		held, _ := m.Acquire(context.Background(), 4, 4)
		defer held.Release()
		req := signedConcreteRequest(t, []byte("body"))
		next := false
		h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 4, Part: 4})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "SlowDown") || next {
			t.Fatalf("status=%d next=%v body=%s", rec.Code, next, rec.Body.String())
		}
	})
	t.Run("control-xml-request-limit", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), (1<<20)+1)
		req := signedConcreteRequest(t, body)
		req.Method = http.MethodPost
		resignV4Request(t, req, fmt.Sprintf("%x", sha256.Sum256(body)))
		read := false
		req.Body = trackingBody{Reader: bytes.NewReader(body), read: &read}
		m := NewSpoolManager(2 << 20).(*spoolManager)
		rec := httptest.NewRecorder()
		AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 2 << 20, Part: 64})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") })).ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "EntityTooLarge") || read || m.CurrentBytes() != 0 {
			t.Fatalf("status=%d read=%v bytes=%d", rec.Code, read, m.CurrentBytes())
		}
	})
}

func TestLiveSpoolLimitSourceAffectsStreamingLimit(t *testing.T) {
	source := NewSpoolLimitSource(SpoolLimits{Global: 4, Part: 4})
	r := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", nil)
	if got := spoolLimitForRequest(r, source.Limits().Global, source.Limits().Part); got != 4 {
		t.Fatalf("initial streaming limit=%d", got)
	}
	source.Set(SpoolLimits{Global: 8, Part: 2})
	if got := spoolLimitForRequest(r, source.Limits().Global, source.Limits().Part); got != 8 {
		t.Fatalf("reloaded streaming limit=%d", got)
	}
	part := httptest.NewRequest(http.MethodPut, "http://example.test/b/k?partNumber=1&uploadId=u", nil)
	if got := spoolLimitForRequest(part, source.Limits().Global, source.Limits().Part); got != 2 {
		t.Fatalf("reloaded part streaming limit=%d", got)
	}
}

func TestSpoolLimitForRequest_OperationMatrix(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		copySource bool
		want       int64
	}{
		{name: "put-object", target: "/bucket/key", want: 8 << 20},
		{name: "copy-object", target: "/bucket/key", copySource: true, want: 1 << 20},
		{name: "upload-part", target: "/bucket/key?partNumber=1&uploadId=u", want: 2 << 20},
		{name: "bucket-policy", target: "/bucket?policy", want: 1 << 20},
		{name: "bucket-lifecycle", target: "/bucket?lifecycle", want: 1 << 20},
		{name: "bucket-acl", target: "/bucket?acl", want: 1 << 20},
		{name: "bucket-cors", target: "/bucket?cors", want: 1 << 20},
		{name: "bucket-encryption", target: "/bucket?encryption", want: 1 << 20},
		{name: "object-acl", target: "/bucket/key?acl", want: 1 << 20},
		{name: "object-tagging", target: "/bucket/key?tagging", want: 1 << 20},
		{name: "object-retention", target: "/bucket/key?retention", want: 1 << 20},
		{name: "object-legal-hold", target: "/bucket/key?legal-hold", want: 1 << 20},
		{name: "complete", target: "/bucket/key?uploadId=u", want: 1 << 20},
		{name: "deceptive-part-number", target: "/bucket/key?partNumber=1", want: 1 << 20},
		{name: "deceptive-upload-id", target: "/bucket/key?uploadId=u", want: 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, tt.target, nil)
			if tt.copySource {
				r.Header.Set("X-Amz-Copy-Source", "/source-bucket/source-key")
			}
			if got := spoolLimitForRequest(r, 8<<20, 2<<20); got != tt.want {
				t.Fatalf("limit=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestAuthMiddleware_ControlXMLPutRejectedBeforeReadOrSpool(t *testing.T) {
	routes := []string{"/bucket?policy", "/bucket?lifecycle", "/bucket/key?acl", "/bucket/key?tagging", "/bucket/key?retention", "/bucket/key?legal-hold"}
	for _, target := range routes {
		t.Run(target, func(t *testing.T) {
			body := bytes.Repeat([]byte("x"), (1<<20)+1)
			req := signedConcreteRequest(t, body)
			parts := strings.SplitN(target, "?", 2)
			req.URL.Path = parts[0]
			if len(parts) == 2 {
				req.URL.RawQuery = parts[1]
			}
			resignV4Request(t, req, fmt.Sprintf("%x", sha256.Sum256(body)))
			read := false
			req.Body = trackingBody{Reader: bytes.NewReader(body), read: &read}
			dir := t.TempDir()
			m := NewSpoolManager(8<<20, dir)
			next := false
			h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 8 << 20, Part: 2 << 20})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			entries, _ := os.ReadDir(dir)
			if rec.Code != http.StatusRequestEntityTooLarge || next || read || m.(*spoolManager).CurrentBytes() != 0 || len(entries) != 0 {
				t.Fatalf("status=%d next=%v read=%v bytes=%d files=%d", rec.Code, next, read, m.(*spoolManager).CurrentBytes(), len(entries))
			}
		})
	}
}

func TestAuthMiddleware_CopyObjectUsesControlXMLLimit(t *testing.T) {
	body := bytes.Repeat([]byte("x"), (1<<20)+1)
	req := signedConcreteRequest(t, body)
	req.Header.Set("X-Amz-Copy-Source", "/source-bucket/source-key")
	resignV4Request(t, req, fmt.Sprintf("%x", sha256.Sum256(body)))
	read := false
	req.Body = trackingBody{Reader: bytes.NewReader(body), read: &read}
	dir := t.TempDir()
	m := NewSpoolManager(8<<20, dir)
	next := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 8 << 20, Part: 2 << 20})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	entries, _ := os.ReadDir(dir)
	if rec.Code != http.StatusRequestEntityTooLarge || next || read || m.(*spoolManager).CurrentBytes() != 0 || len(entries) != 0 {
		t.Fatalf("status=%d next=%v read=%v bytes=%d files=%d", rec.Code, next, read, m.(*spoolManager).CurrentBytes(), len(entries))
	}
}

func TestAuthMiddlewareUsesReloadedLiveVerifiedLimit(t *testing.T) {
	source := NewSpoolLimitSource(SpoolLimits{Global: 4, Part: 4})
	m := NewSpoolManager(32)
	nextCalls := 0
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, source)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalls++
	}))
	makeRequest := func() *httptest.ResponseRecorder {
		body := bytes.Repeat([]byte("x"), 8)
		req := signedConcreteRequest(t, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := makeRequest(); rec.Code != http.StatusRequestEntityTooLarge || nextCalls != 0 {
		t.Fatalf("before reload status=%d next=%d", rec.Code, nextCalls)
	}
	source.Set(SpoolLimits{Global: 16, Part: 16})
	if rec := makeRequest(); rec.Code != http.StatusOK || nextCalls != 1 {
		t.Fatalf("after reload status=%d next=%d", rec.Code, nextCalls)
	}
}

func TestSpoolManager_CrossPathAggregateLimit(t *testing.T) {
	m := NewSpoolManager(4).(*spoolManager)
	reservation, err := m.Acquire(context.Background(), 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	awsRequest := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", bytes.NewBufferString("1\r\na\r\n0\r\nx-amz-checksum-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\n\r\n"))
	awsRequest.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	awsRequest.Header.Set("x-amz-trailer", "x-amz-checksum-sha256")
	awsRequest.Header.Set("content-encoding", "aws-chunked")
	awsRequest.Header.Set("x-amz-decoded-content-length", "1")
	if _, err := verifyAndSpoolAWSBody(awsRequest, nil, m, int64(4)); !errors.Is(err, ErrSpoolCapacity) {
		t.Fatalf("AWS-chunked acquisition error=%v", err)
	}
	reservation.Release()
	body := []byte("test")
	sum := sha256.Sum256(body)
	r := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	concrete, err := m.Acquire(context.Background(), 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAndSpoolV4Payload(r, &V4SigningContext{verifyPayload: true, expectedPayloadHash: sum}, m, int64(4)); !errors.Is(err, ErrSpoolCapacity) {
		t.Fatalf("concrete acquisition error=%v", err)
	}
	concrete.Release()
	if got := m.CurrentBytes(); got != 0 {
		t.Fatalf("bytes=%d", got)
	}
}

func TestAuthMiddleware_SuccessReleasesSharedReservation(t *testing.T) {
	body := []byte("successful signed body")
	req := signedConcreteRequest(t, body)
	m := NewSpoolManager(64).(*spoolManager)
	next := httptest.NewRecorder()
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true, m, SpoolLimits{Global: 64, Part: 64})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, err := io.ReadAll(r.Body); err != nil || !bytes.Equal(got, body) {
			t.Fatalf("next body=%q err=%v", got, err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(next, req)
	if next.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", next.Code, next.Body.String())
	}
	if got := m.CurrentBytes(); got != 0 {
		t.Fatalf("shared manager retained %d bytes after successful request", got)
	}
}

func TestSpoolDirectoryIsUsedAndCleanupIsExact(t *testing.T) {
	dir := t.TempDir()
	m := NewSpoolManager(32, dir)
	body := []byte("payload")
	sum := sha256.Sum256(body)
	r := httptest.NewRequest(http.MethodPut, "http://example.test/b/k", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	s := &V4SigningContext{verifyPayload: true, expectedPayloadHash: sum}
	spool, err := verifyAndSpoolV4Payload(r, s, m, int64(32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(spool.(*verifiedAWSFile).path)); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	_ = spool.Close()
	if _, err := io.ReadAll(spool); err == nil { /* closed reader behavior is platform-specific */
	}
	if got := m.(*spoolManager).CurrentBytes(); got != 0 {
		t.Fatalf("bytes=%d", got)
	}
}

func TestSpoolAcquireHonorsCancellationAndSentinels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := NewSpoolManager(10)
	if _, err := m.Acquire(ctx, 0, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if _, err := m.Acquire(context.Background(), 2, 1); !errors.Is(err, ErrSpoolRequestLimit) {
		t.Fatalf("err=%v", err)
	}
}
