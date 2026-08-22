package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type sec39ErrorEngine struct{ err error }

func (e *sec39ErrorEngine) Encrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, e.err
}
func (e *sec39ErrorEngine) Decrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, e.err
}
func (e *sec39ErrorEngine) DecryptRange(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error) {
	return nil, nil, e.err
}
func (e *sec39ErrorEngine) AuthenticateChunkedTrailer(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64) (crypto.ChunkedObjectInfo, error) {
	return crypto.ChunkedObjectInfo{}, e.err
}
func (*sec39ErrorEngine) IsEncrypted(map[string]string) bool { return true }
func (*sec39ErrorEngine) PreferredAlgorithm() string         { return crypto.AlgorithmAES256GCM }

func assertSEC39InternalError(t *testing.T, w *httptest.ResponseRecorder, forbidden ...string) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "<Code>InternalError</Code>") || !strings.Contains(body, "We encountered an internal error. Please try again.") {
		t.Fatalf("missing canonical XML error: %s", body)
	}
	for _, secret := range append([]string{"requested", "maximum", "100001", "2000001", "2000000", "65536", "ciphertext", "plaintext"}, forbidden...) {
		if strings.Contains(strings.ToLower(body), secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
}

func TestSEC39_HandleGetObject_KDFErrorFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"invalid", &crypto.ErrInvalidKDFParams{Algorithm: crypto.KDFAlgPBKDF2SHA256, Parameter: "iterations", Value: 1}},
		{"cost", &crypto.ErrKDFCostTooHigh{Algorithm: crypto.KDFAlgPBKDF2SHA256, Parameter: "iterations", Requested: 2000001, Maximum: 2000000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockS3Client()
			client.objects["bucket/key"] = []byte("backend-ciphertext")
			client.metadata["bucket/key"] = map[string]string{crypto.MetaEncrypted: "true"}
			h := NewHandler(client, &sec39ErrorEngine{err: fmt.Errorf("decrypt failed: %w", tc.err)}, logrus.New(), getTestMetrics())
			r := mux.NewRouter()
			h.RegisterRoutes(r)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/bucket/key", nil))
			assertSEC39InternalError(t, w, "backend-ciphertext")
			if strings.Contains(w.Body.String(), "backend-ciphertext") {
				t.Fatal("ciphertext was returned")
			}
		})
	}
}

func TestSEC39_ForwardedGet_KDFErrorFailsClosed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Meta-Encrypted", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ciphertext"))
	}))
	defer backend.Close()
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"invalid", &crypto.ErrInvalidKDFParams{Algorithm: crypto.KDFAlgArgon2id, Parameter: "time", Value: 0}},
		{"cost", &crypto.ErrKDFCostTooHigh{Algorithm: crypto.KDFAlgArgon2id, Parameter: "memory", Requested: 2000000, Maximum: 65536}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(nil, &sec39ErrorEngine{err: fmt.Errorf("decrypt failed: %w", tc.err)}, logrus.New(), getTestMetrics())
			h.config = &config.Config{Backend: config.BackendConfig{Endpoint: backend.URL, AccessKey: "a", SecretKey: "b", Region: "us-east-1"}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/bucket/key", nil)
			h.forwardSignatureV4Request(w, r, "GET", "bucket", "key", time.Now())
			assertSEC39InternalError(t, w, "backend-ciphertext")
		})
	}
}
