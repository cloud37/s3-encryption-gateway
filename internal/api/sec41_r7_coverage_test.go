package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type sec41FailWriter struct{}

func (sec41FailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type sec41CancelReader struct{}

func (sec41CancelReader) Read([]byte) (int, error) { return 0, context.Canceled }

type sec41FailHash struct{}

func (sec41FailHash) Write([]byte) (int, error) { return 0, errors.New("hash failed") }

type sec41TrailerErrorReader struct {
	data []byte
	done bool
}

func (r *sec41TrailerErrorReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	if !r.done {
		r.done = true
		return 0, errors.New("trailer read failed")
	}
	return 0, io.EOF
}

func sec41Context() *V4SigningContext {
	return &V4SigningContext{
		timestamp: "20130524T000000Z", credentialScope: "scope",
		signingKey: []byte("coverage-key"), seedSignature: sha256.Sum256([]byte("seed")),
		mode: streamingSignedPayload,
	}
}

func TestSEC41R7ReaderHelperErrors(t *testing.T) {
	if _, err := readAWSLine(bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 20)), 4), 8); !errors.Is(err, ErrStreamingFraming) {
		t.Fatalf("long line error = %v", err)
	}
	if err := copyChunk(bufio.NewReader(sec41CancelReader{}), io.Discard, nil, 1, nil); !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("context reader error = %v", err)
	}
	if err := copyChunk(bufio.NewReader(strings.NewReader("x")), sec41FailWriter{}, nil, 1, nil); err == nil {
		t.Fatal("write failure accepted")
	}
	if err := copyChunk(bufio.NewReader(strings.NewReader("x")), io.Discard, sec41FailHash{}, 1, nil); err == nil {
		t.Fatal("hash failure accepted")
	}
	done := make(chan struct{})
	close(done)
	if err := copyChunk(bufio.NewReader(strings.NewReader("x")), io.Discard, nil, 1, done); !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	for _, tc := range []struct {
		value string
		width int
		want  bool
	}{
		{"", 0, true}, {"0", 2, false}, {"A", 1, false}, {"g", 1, false},
	} {
		if got := validLowerHex(tc.value, tc.width); got != tc.want {
			t.Errorf("validLowerHex(%q,%d)=%v", tc.value, tc.width, got)
		}
	}
	if decodeSignature(make([]byte, 32), "bad") == nil || decodeSignature(make([]byte, 31), strings.Repeat("0", 64)) == nil {
		t.Fatal("invalid signature accepted")
	}
	for _, input := range []string{"\r", "x\n", "\rx"} {
		if err := expectCRLF(bufio.NewReader(strings.NewReader(input))); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestSEC41R7VerifierErrorAndCancellationBranches(t *testing.T) {
	if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader("1\r\nx\r\n0\r\n")), sec41FailWriter{}, nil, -1, false, nil); !errors.Is(err, ErrStreamingSpool) {
		t.Fatalf("destination failure: %v", err)
	}
	closed := sec41Context()
	closed.Close()
	if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader("0\r\n")), io.Discard, closed, -1, false, nil); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("closed context: %v", err)
	}
	done := make(chan struct{})
	close(done)
	if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader("0\r\n")), io.Discard, nil, -1, false, done); !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("cancelled verifier: %v", err)
	}
	for _, input := range []string{"", "0\r\nextra"} {
		if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader(input)), io.Discard, nil, -1, false, nil); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	for _, input := range []string{"1\r\nx\r\n0\r\n", "10000001\r\n"} {
		if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader(input)), io.Discard, nil, 0, false, nil); err == nil {
			t.Errorf("accepted length case %q", input)
		}
	}
	for _, input := range []string{"1\r\nx", "1\r\nx\rX0\r\n", "01\r\n", "g\r\n"} {
		if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader(input)), io.Discard, nil, -1, false, nil); err == nil {
			t.Errorf("accepted framing %q", input)
		}
	}
	for _, input := range []string{"1;chunk-signature=\r\nx\r\n", "1;chunk-signature=" + strings.Repeat("0", 64) + ";x\r\nx\r\n", "1;chunk-signature=" + strings.Repeat("0", 63) + "\r\nx\r\n"} {
		if _, _, err := verifyAWSChunkedContext(bufio.NewReader(strings.NewReader(input)), io.Discard, sec41Context(), -1, false, nil); err == nil {
			t.Errorf("accepted signed framing %q", input)
		}
	}
	c := sec41Context()
	if err := verifyChunkSignatureHash(nil, [32]byte{}, strings.Repeat("0", 64), make([]byte, 32)); err == nil {
		t.Fatal("nil signing context accepted")
	}
	if err := verifyChunkSignatureHash(c, [32]byte{}, strings.Repeat("0", 64), []byte{1}); err == nil {
		t.Fatal("bad hash length path not exercised")
	}
	if err := verifyChunkSignatureHash(c, [32]byte{}, strings.Repeat("0", 64), make([]byte, 32)); err == nil {
		t.Fatal("mismatch accepted")
	}
	c.Close()
	if err := verifyChunkSignature(c, [32]byte{}, strings.Repeat("0", 64), nil); err == nil {
		t.Fatal("closed signature context accepted")
	}
}

func TestSEC41R7TrailerValidationBranches(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "body")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("payload"); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, tc := range []struct {
		declaration string
		body        string
	}{
		{"", "\r\n"}, {"x-amz-checksum-sha256,x-amz-checksum-sha256", "\r\n"},
		{"X-Amz-Checksum-SHA256", "\r\n"}, {"x-amz-checksum-unknown", "\r\n"},
		{"x-amz-checksum-sha256", "bad line\r\n\r\n"},
		{"x-amz-checksum-sha256", "x-amz-checksum-sha256: bad\r\n\r\n"},
	} {
		if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader(tc.body)), f, tc.declaration, nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
			t.Errorf("accepted trailer case %q/%q", tc.declaration, tc.body)
		}
	}
	longDecl := strings.TrimSuffix(strings.Repeat("x-amz-checksum-sha256,", maxAWSTrailerCount+1), ",")
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("\r\n")), f, longDecl, nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("oversized declaration accepted")
	}
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("\r\n")), f, "x-amz-checksum-sha256", nil, streamingSignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("nil signed context accepted")
	}
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("x-amz-checksum-sha256: bad\r\n\r\n")), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("bad checksum trailer accepted")
	}
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("x-amz-checksum-sha256: bad\r\n\r\nextra")), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("trailing trailer data accepted")
	}
	for _, body := range []string{
		"x-amz-checksum-sha256: bad\n",
		"x-amz-checksum-sha256: \r\n\r\n",
		"x-amz-checksum-sha256: bad\r\nX-Amz-Checksum-SHA256: bad\r\n\r\n",
		"x-amz-checksum-sha256: bad\r\nx-amz-checksum-sha256: bad\r\n\r\n",
		"x-amz-checksum-sha256: bad\r\nx-amz-trailer-signature: bad\r\n\r\n",
	} {
		if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader(body)), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
			t.Errorf("accepted malformed trailer %q", body)
		}
	}
	mismatch := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
	mismatch.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	mismatch.Header.Set("Content-Encoding", "aws-chunked")
	mismatch.Header.Set("X-Amz-Decoded-Content-Length", "0")
	mismatchSigning := sec41Context()
	if _, err := verifyAndSpoolAWSBody(mismatch, mismatchSigning); !errors.Is(err, ErrStreamingFraming) {
		t.Fatalf("mode mismatch: %v", err)
	}
	mismatchSigning.Close()
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("\r\n")), f, "x-amz-checksum-sha256", sec41Context(), streamingSignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("missing signed trailer rejected")
	}
	for _, body := range []string{
		"x-amz-checksum-sha256: AA==\r\n\r\n",
		"x-amz-checksum-sha256: " + strings.Repeat("A", 44) + "\r\n\r\n",
		"x-amz-checksum-sha256: " + "bad\r\nx-amz-checksum-sha256: bad\r\n\r\n",
	} {
		if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader(body)), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
			t.Errorf("accepted checksum trailer %q", body)
		}
	}
	if err := verifyTrailerChecksums(f, nil); err == nil {
		t.Fatal("empty checksums accepted")
	}
	data := []byte("payload")
	digest := sha256.Sum256(data)
	validValue := base64.StdEncoding.EncodeToString(digest[:])
	validTrailer := "x-amz-checksum-sha256: " + base64.StdEncoding.EncodeToString(digest[:]) + "\r\n\r\n"
	reader := &sec41TrailerErrorReader{data: []byte(validTrailer)}
	if err := verifyAWSTrailers(bufio.NewReader(reader), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("trailer reader error accepted")
	}
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader(validTrailer)), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err != nil {
		t.Fatalf("valid direct trailer: %v", err)
	}
	for _, body := range []string{
		"x-amz-checksum-sha256: " + validValue + "\r\n\r\nextra",
		"x-amz-checksum-sha256: " + validValue + "\r\nX-Amz-Checksum-SHA256: " + validValue + "\r\n\r\n",
		"x-amz-checksum-sha256: " + validValue + "\r\nx-amz-checksum-sha256: " + validValue + "\r\n\r\n",
		"x-amz-checksum-sha256: " + validValue + "\r\nx-amz-trailer-signature: bad\r\n\r\n",
	} {
		if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader(body)), f, "x-amz-checksum-sha256", nil, streamingUnsignedPayloadTrailer, [32]byte{}); err == nil {
			t.Errorf("accepted post-parse trailer %q", body)
		}
	}
	for _, name := range []string{"x-amz-checksum-sha256", "x-amz-checksum-sha1", "x-amz-checksum-crc32", "x-amz-checksum-crc32c"} {
		if err := verifyTrailerChecksums(f, map[string]string{name: base64.StdEncoding.EncodeToString([]byte("wrong"))}); err == nil {
			t.Errorf("accepted mismatched %s", name)
		}
	}
	if err := verifyAWSTrailers(bufio.NewReader(strings.NewReader("x-amz-checksum-sha256: "+base64.StdEncoding.EncodeToString(digest[:])+"\r\n\r\n")), f, "x-amz-checksum-sha256", sec41Context(), streamingSignedPayloadTrailer, [32]byte{}); err == nil {
		t.Fatal("accepted missing trailer signature")
	}
	if err := verifyTrailerChecksums(f, map[string]string{"x-amz-checksum-sha256": "bad"}); err == nil {
		t.Fatal("bad checksum accepted")
	}
	for _, token := range []string{"", "Upper", "bad space", "bad\\"} {
		if validTrailerToken(token) {
			t.Errorf("validTrailerToken(%q)=true", token)
		}
	}
	if !validTrailerToken("x-amz_checksum") {
		t.Fatal("valid token rejected")
	}
}

func TestSEC41R7SpoolAndResponseBranches(t *testing.T) {
	for _, tc := range []struct {
		sha, encoding, length string
		signing               *V4SigningContext
	}{
		{"STREAMING-UNKNOWN", "aws-chunked", "1", nil},
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "", "1", sec41Context()},
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "aws-chunked", "1", nil},
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", "aws-chunked", "1", nil},
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", "aws-chunked", "-1", nil},
	} {
		r := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
		r.Header.Set("X-Amz-Content-Sha256", tc.sha)
		r.Header.Set("Content-Encoding", tc.encoding)
		r.Header.Set("X-Amz-Decoded-Content-Length", tc.length)
		if _, err := verifyAndSpoolAWSBody(r, tc.signing); err == nil {
			t.Errorf("accepted spool case %+v", tc)
		}
	}
	trailer := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
	trailer.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	trailer.Header.Set("Content-Encoding", "aws-chunked")
	trailer.Header.Set("X-Amz-Decoded-Content-Length", "0")
	trailer.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
	trailer.Body = io.NopCloser(strings.NewReader("0\r\n"))
	if _, err := verifyAndSpoolAWSBody(trailer, nil); err == nil {
		t.Fatal("missing trailer block accepted")
	}
	for _, tc := range []struct{ sha, encoding, length string }{
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", "aws-chunked", ""},
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", "aws-chunked", "1"},
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "aws-chunked", "1"},
	} {
		r := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
		r.Header.Set("X-Amz-Content-Sha256", tc.sha)
		r.Header.Set("Content-Encoding", tc.encoding)
		if tc.length != "" {
			r.Header.Set("X-Amz-Decoded-Content-Length", tc.length)
		}
		if _, err := verifyAndSpoolAWSBody(r, nil); err == nil {
			t.Errorf("accepted missing-context case %+v", tc)
		}
	}
	for _, tc := range []struct {
		encoding, length string
		headers          []string
	}{
		{"aws-chunked, aws-chunked", "1", nil},
		{"identity", "1", nil},
		{"aws-chunked", "1", []string{"1", "1"}},
		{"aws-chunked", "9223372036854775808", nil},
	} {
		r := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
		r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		r.Header.Set("Content-Encoding", tc.encoding)
		r.Header.Set("X-Amz-Decoded-Content-Length", tc.length)
		for _, value := range tc.headers {
			r.Header.Add("X-Amz-Decoded-Content-Length", value)
		}
		if _, err := verifyAndSpoolAWSBody(r, nil); err == nil {
			t.Errorf("accepted header case %+v", tc)
		}
	}
	cancel := httptest.NewRequest("PUT", "http://example.test", strings.NewReader("0\r\n"))
	cancel = cancel.WithContext(func() context.Context { ctx, stop := context.WithCancel(context.Background()); stop(); return ctx }())
	cancel.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	cancel.Header.Set("Content-Encoding", "aws-chunked")
	cancel.Header.Set("X-Amz-Decoded-Content-Length", "0")
	if _, err := verifyAndSpoolAWSBody(cancel, nil); !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("cancelled spool: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	wrapped := &verifiedAWSFile{File: f, path: path}
	if err := wrapped.Close(); err == nil {
		t.Fatal("close error path not returned")
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	for _, e := range []error{ErrUnsupportedStreamingMode, ErrStreamingFraming, ErrStreamingLength, ErrIncompleteBody, ErrStreamingCanceled, ErrSignatureMismatch, ErrStreamingSpool} {
		w := httptest.NewRecorder()
		writeStreamingPayloadError(w, "/bucket/key", e)
		if w.Code == 0 || !strings.Contains(w.Body.String(), "<Code>") {
			t.Fatalf("response for %v = %d %q", e, w.Code, w.Body.String())
		}
	}
}

func TestSEC41SpoolOperationFailures(t *testing.T) {
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	newFile := func(t *testing.T) *os.File {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "sec41-spool-")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	request := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader(body))
		r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		r.Header.Set("Content-Encoding", "aws-chunked")
		r.Header.Set("X-Amz-Decoded-Content-Length", "1")
		r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
		return r
	}
	t.Run("create", func(t *testing.T) {
		streamingSpoolOps = original
		streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("create") }
		_, err := verifyAndSpoolAWSBody(request("0\r\n"), nil)
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("chmod", func(t *testing.T) {
		streamingSpoolOps = original
		streamingSpoolOps.chmod = func(*os.File, os.FileMode) error { return errors.New("chmod") }
		_, err := verifyAndSpoolAWSBody(request("0\r\n"), nil)
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("write", func(t *testing.T) {
		streamingSpoolOps = original
		streamingSpoolOps.write = func(*os.File, []byte) (int, error) { return 0, errors.New("write") }
		_, err := verifyAndSpoolAWSBody(request("1\r\nx\r\n0\r\n\r\n"), nil)
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("seek", func(t *testing.T) {
		streamingSpoolOps = original
		streamingSpoolOps.seek = func(*os.File, int64, int) (int64, error) { return 0, errors.New("seek") }
		_, err := verifyAndSpoolAWSBody(request("1\r\nx\r\n0\r\n\r\n"), nil)
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("read", func(t *testing.T) {
		streamingSpoolOps = original
		streamingSpoolOps.read = func(*os.File, []byte) (int, error) { return 0, errors.New("read") }
		_, err := verifyAndSpoolAWSBody(request("1\r\nx\r\n0\r\nx-amz-checksum-sha256: bad\r\n\r\n"), nil)
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("close", func(t *testing.T) {
		streamingSpoolOps = original
		f := newFile(t)
		streamingSpoolOps.close = func(*os.File) error { return errors.New("close") }
		err := (&verifiedAWSFile{File: f, path: f.Name()}).Close()
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
	})
	t.Run("remove", func(t *testing.T) {
		streamingSpoolOps = original
		f := newFile(t)
		streamingSpoolOps.remove = func(string) error { return errors.New("remove") }
		err := (&verifiedAWSFile{File: f, path: f.Name()}).Close()
		if !errors.Is(err, ErrStreamingSpool) {
			t.Fatal(err)
		}
		_ = f.Close()
	})

	// This follows the real authenticated PUT path through the error mapper.
	streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("handler create") }
	client := newMockS3Client()
	engine, err := crypto.NewEngine([]byte("test-password-0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	w := httptest.NewRecorder()
	sec41AuthedRouter(router).ServeHTTP(w, sec41AuthChunkedRequest(http.MethodPut, "/bucket/spool-error", [][]byte{{'x'}}, -1))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "<Code>InternalError</Code>") || !strings.Contains(w.Body.String(), "We encountered an internal error. Please try again.") || client.putObjectCallCount != 0 {
		t.Fatalf("handler spool failure: status=%d body=%s puts=%d", w.Code, w.Body.String(), client.putObjectCallCount)
	}
}

func TestSEC41AuthMiddleware_AuditFailureAndStreamingHeaderPaths(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	auditLogger := audit.NewLogger(20, nil)
	h := AuthMiddleware(testCredentialStore(), time.Minute, logger, auditLogger, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Authenticated requests with unsupported streaming headers must be mapped
	// by the middleware, not deferred to a handler.
	r := sec41AuthRequestBody(http.MethodPut, "/bucket/audit", "STREAMING-UNKNOWN", "", 0, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>InvalidRequest</Code>") {
		t.Fatalf("invalid streaming auth path: %d %s", w.Code, w.Body.String())
	}
	if len(auditLogger.GetEvents()) == 0 {
		t.Fatal("streaming auth failure did not emit audit event")
	}
}

type sec41LookupErrorStore struct{}

func (sec41LookupErrorStore) Lookup(string) (string, string, error) {
	return "", "", errors.New("lookup failed")
}

func TestSEC41R7AuthMiddlewareFailureMatrix(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	for _, tc := range []struct {
		name  string
		store CredentialStore
		url   string
		v2    bool
	}{
		{"lookup error", sec41LookupErrorStore{}, "/bucket?AWSAccessKeyId=key&Signature=x&Expires=1893456000", true},
		{"unrecognized", testCredentialStore(), "/bucket?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE", true},
		{"v2 disabled", testCredentialStore(), "/bucket?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=x&Expires=1893456000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := AuthMiddleware(tc.store, time.Minute, logger, nil, tc.v2)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			r := httptest.NewRequest("GET", tc.url, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == http.StatusOK {
				t.Fatal("failure request accepted")
			}
		})
	}
}

func TestSEC41StreamingHeaderValidationMatrix(t *testing.T) {
	base := func(mode streamingPayloadMode) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader("0\r\n"))
		r.Header.Set("X-Amz-Content-Sha256", map[streamingPayloadMode]string{
			streamingSignedPayload:          "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			streamingSignedPayloadTrailer:   "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
			streamingUnsignedPayloadTrailer: "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		}[mode])
		r.Header.Set("Content-Encoding", "aws-chunked")
		r.Header.Set("X-Amz-Decoded-Content-Length", "0")
		return r
	}
	for _, tc := range []struct {
		name   string
		mode   streamingPayloadMode
		mutate func(*http.Request)
		want   error
	}{
		{"content encoding absent", streamingSignedPayload, func(r *http.Request) { r.Header.Del("Content-Encoding") }, ErrStreamingFraming},
		{"content encoding multiple", streamingSignedPayload, func(r *http.Request) { r.Header.Add("Content-Encoding", "identity") }, ErrStreamingFraming},
		{"content encoding malformed", streamingSignedPayload, func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") }, ErrStreamingFraming},
		{"decoded length absent", streamingSignedPayload, func(r *http.Request) { r.Header.Del("X-Amz-Decoded-Content-Length") }, ErrStreamingFraming},
		{"decoded length multiple", streamingSignedPayload, func(r *http.Request) { r.Header.Add("X-Amz-Decoded-Content-Length", "0") }, ErrStreamingFraming},
		{"decoded length negative", streamingUnsignedPayloadTrailer, func(r *http.Request) {
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			r.Header.Set("X-Amz-Decoded-Content-Length", "-1")
			r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
		}, ErrStreamingFraming},
		{"decoded length non-int", streamingUnsignedPayloadTrailer, func(r *http.Request) {
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			r.Header.Set("X-Amz-Decoded-Content-Length", "nope")
			r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
		}, ErrStreamingFraming},
		{"trailer required", streamingSignedPayloadTrailer, func(*http.Request) {}, ErrStreamingTrailer},
		{"trailer required unsigned", streamingUnsignedPayloadTrailer, func(*http.Request) {}, ErrStreamingTrailer},
		{"trailer multiple", streamingUnsignedPayloadTrailer, func(r *http.Request) {
			r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
			r.Header.Add("X-Amz-Trailer", "x-amz-checksum-sha1")
		}, ErrStreamingTrailer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base(tc.mode)
			tc.mutate(r)
			if tc.name == "decoded length negative" || tc.name == "decoded length non-int" {
				if _, err := verifyAndSpoolAWSBody(r, nil); !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
				return
			}
			if err := validateStreamingRequestHeaders(r, tc.mode); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
	valid := base(streamingSignedPayload)
	if err := validateStreamingRequestHeaders(valid, streamingSignedPayload); err != nil {
		t.Fatalf("valid headers rejected: %v", err)
	}
	trailer := base(streamingUnsignedPayloadTrailer)
	trailer.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
	if err := validateStreamingRequestHeaders(trailer, streamingUnsignedPayloadTrailer); err != nil {
		t.Fatalf("valid trailer headers rejected: %v", err)
	}
	if err := validateStreamingRequestHeaders(valid, streamingNone); err != nil {
		t.Fatalf("non-streaming headers rejected: %v", err)
	}
}

func TestSEC41StreamingContextLookupAndCloseRules(t *testing.T) {
	if got := streamingContext(nil); got != nil {
		t.Fatal("nil request returned a context")
	}
	r := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
	if got := streamingContext(r); got != nil {
		t.Fatal("missing context returned a value")
	}
	c := sec41Context()
	r = r.WithContext(context.WithValue(r.Context(), v4SigningContextKey{}, c))
	if got := streamingContext(r); got != c {
		t.Fatal("stored context was not returned")
	}
	var nilContext *V4SigningContext
	nilContext.Close()
	c.Close()
	c.Close()
	if !c.closed || c.signingKey != nil || c.seedSignature != [32]byte{} {
		t.Fatal("close rules did not preserve an already-closed zeroized context")
	}
}

var _ = bytes.Compare
