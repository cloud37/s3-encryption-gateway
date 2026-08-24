package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func signedConcreteRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest("PUT", "/bucket/key", bytes.NewReader(body))
	r.Host = "localhost"
	now := time.Now().UTC()
	timestamp, date := now.Format("20060102T150405Z"), now.Format("20060102")
	r.Header.Set("X-Amz-Date", timestamp)
	r.Header.Set("X-Amz-Content-Sha256", fmt.Sprintf("%x", sha256.Sum256(body)))
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonical, err := createCanonicalRequest(r, false, signed)
	if err != nil {
		t.Fatal(err)
	}
	scope := date + "/us-east-1/s3/aws4_request"
	key := getSignatureKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "s3")
	sig := hex.EncodeToString(sign(key, []byte(createStringToSign(timestamp, scope, canonical))))
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)
	return r
}

func concreteSigning(data []byte) *V4SigningContext {
	return &V4SigningContext{expectedPayloadHash: sha256.Sum256(data), verifyPayload: true}
}

func TestVerifyAndSpoolV4Payload_ValidDigest(t *testing.T) {
	data := []byte("verified body")
	closed := false
	r := httptest.NewRequest("PUT", "/", closeTrackingBody{Reader: bytes.NewReader(data), closed: &closed})
	spool, err := verifyAndSpoolV4Payload(r, concreteSigning(data))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	got, err := io.ReadAll(spool)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("body = %q, err = %v", got, err)
	}
	if spool.DecodedLength() != int64(len(data)) {
		t.Fatalf("length = %d", spool.DecodedLength())
	}
	if !closed {
		t.Fatal("original body was not closed")
	}
}

func TestVerifyAndSpoolV4Payload_DigestMismatchRemovesSpool(t *testing.T) {
	original := streamingSpoolOps
	var path string
	streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := original.createTemp(dir, pattern)
		if err == nil {
			path = f.Name()
		}
		return f, err
	}
	t.Cleanup(func() { streamingSpoolOps = original })
	r := httptest.NewRequest("PUT", "/", bytes.NewReader([]byte("tampered")))
	_, err := verifyAndSpoolV4Payload(r, concreteSigning([]byte("original")))
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("err = %v", err)
	}
	if path == "" {
		t.Fatal("spool path was not captured")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("spool remains: %v", statErr)
	}
}

func TestVerifyAndSpoolV4Payload_ReadWriteSeekAndCreateFailures(t *testing.T) {
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	cases := []struct {
		name string
		set  func()
	}{
		{"create", func() {
			streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("create") }
		}},
		{"chmod", func() { streamingSpoolOps.chmod = func(*os.File, os.FileMode) error { return errors.New("chmod") } }},
		{"read", func() {
			streamingSpoolOps.readRequestBody = func(io.Reader, []byte) (int, error) { return 0, errors.New("read") }
		}},
		{"write", func() {
			streamingSpoolOps.write = func(*os.File, []byte) (int, error) { return 0, errors.New("write") }
		}},
		{"seek", func() {
			streamingSpoolOps.seek = func(*os.File, int64, int) (int64, error) { return 0, errors.New("seek") }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			streamingSpoolOps = original
			var path string
			created := false
			streamingSpoolOps.createTemp = func(d, p string) (*os.File, error) {
				f, err := original.createTemp(d, p)
				if err == nil {
					created, path = true, f.Name()
				}
				return f, err
			}
			tc.set()
			closed := false
			var body io.ReadCloser = closeTrackingBody{Reader: bytes.NewReader([]byte("body")), closed: &closed}
			if tc.name == "read" {
				body = closeTrackingErrorBody{closed: &closed}
			}
			r := httptest.NewRequest("PUT", "/", body)
			_, err := verifyAndSpoolV4Payload(r, concreteSigning([]byte("body")))
			if !errors.Is(err, ErrStreamingSpool) {
				t.Fatalf("err = %v", err)
			}
			if tc.name == "create" && created {
				t.Fatal("create failure created a file")
			}
			if path != "" {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("spool remains: %v", statErr)
				}
			}
			if !closed {
				t.Fatal("original body was not closed")
			}
		})
	}
}

type errReaderRequestBody struct{}

func (errReaderRequestBody) Read([]byte) (int, error) { return 0, errors.New("read") }
func (errReaderRequestBody) Close() error             { return nil }

type closeTrackingErrorBody struct{ closed *bool }

func (b closeTrackingErrorBody) Read([]byte) (int, error) { return 0, errors.New("read") }
func (b closeTrackingErrorBody) Close() error             { *b.closed = true; return nil }

type closeTrackingBody struct {
	io.Reader
	closed *bool
}

func (b closeTrackingBody) Close() error { *b.closed = true; return nil }

func TestVerifyAndSpoolV4Payload_Mode0600AndIdempotentClose(t *testing.T) {
	r := httptest.NewRequest("PUT", "/", bytes.NewReader([]byte("body")))
	spool, err := verifyAndSpoolV4Payload(r, concreteSigning([]byte("body")))
	if err != nil {
		t.Fatal(err)
	}
	f := spool.(*verifiedAWSFile)
	info, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatalf("spool remains: %v", err)
	}
}

func TestVerifyAndSpoolV4Payload_RequestCancellation(t *testing.T) {
	original := streamingSpoolOps
	var path string
	streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := original.createTemp(dir, pattern)
		if err == nil {
			path = f.Name()
		}
		return f, err
	}
	t.Cleanup(func() { streamingSpoolOps = original })
	closed := false
	r := httptest.NewRequest("PUT", "/", closeTrackingBody{Reader: bytes.NewReader([]byte("body")), closed: &closed})
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	_, err := verifyAndSpoolV4Payload(r, concreteSigning([]byte("body")))
	if !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("err = %v", err)
	}
	if path == "" {
		t.Fatal("spool path was not captured")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("spool remains: %v", statErr)
	}
	if !closed {
		t.Fatal("original body was not closed")
	}
}
