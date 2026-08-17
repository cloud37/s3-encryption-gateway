package s3

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// These tests pin the SDK body contract that ADR 0010's retry policy depends on:
// a retry replays the body, so the SDK rewinds it first. A body that is not an
// io.Seeker cannot be rewound and the operation fails instead of retrying. The
// retryer classifies a 500 as retryable, so only a request driven through the
// SDK middleware with a real body exposes this. Callers of PutObject must supply
// a rewindable body — handlePutObject and handleUploadPart use NewSeekableBody.

// nonSeekableReader hides any Seek method on the underlying reader, matching the
// shape of a streaming ciphertext reader or a plain http.Request.Body.
type nonSeekableReader struct{ io.Reader }

// buildRetryTestS3Client is buildTestS3Client with a short, unjittered backoff.
func buildRetryTestS3Client(t *testing.T, transport *countingFaultTransport) Client {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
		Retry: config.BackendRetryConfig{
			InitialBackoff: time.Millisecond,
			MaxBackoff:     5 * time.Millisecond,
			Jitter:         "none",
		},
	}
	factory := NewClientFactory(cfg, WithHTTPTransport(transport))
	c, err := factory.GetClient()
	if err != nil {
		t.Fatalf("GetClient() error: %v", err)
	}
	return c
}

// With a rewindable body a transient 500 is absorbed and the caller never sees it.
func TestS3Client_PutObject_SeekableBody_RetriedAfterTransient500(t *testing.T) {
	payload := []byte("ciphertext-payload")
	body, err := NewSeekableBody(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("NewSeekableBody: %v", err)
	}

	tr := &countingFaultTransport{faultStatus: 500, faultCount: 1}
	client := buildRetryTestS3Client(t, tr)

	_, err = client.PutObject(context.Background(), "bkt", "key", body, nil,
		&body.Len, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject with a seekable body must survive one transient 500, got: %v", err)
	}
	if tr.called != 2 {
		t.Errorf("expected 2 backend attempts (1 fault + 1 retry), got %d", tr.called)
	}
}

// The negative half, and the reason handlePutObject buffers: the retryer decides
// to retry, the rewind fails, and the operation fails instead. If this ever
// starts passing, the buffering in handlePutObject can be revisited.
func TestS3Client_PutObject_NonSeekableBody_CannotRewind(t *testing.T) {
	payload := []byte("ciphertext-payload")
	length := int64(len(payload))
	body := nonSeekableReader{bytes.NewReader(payload)}

	if _, seekable := interface{}(body).(io.Seeker); seekable {
		t.Fatal("test body must not be seekable")
	}

	tr := &countingFaultTransport{faultStatus: 500, faultCount: 1}
	client := buildRetryTestS3Client(t, tr)

	_, err := client.PutObject(context.Background(), "bkt", "key", body, nil,
		&length, "", nil, "", "", "", "", "")
	if err == nil {
		t.Fatal("expected PutObject to fail: a non-seekable body cannot be rewound for retry")
	}
	if !strings.Contains(err.Error(), "rewind") {
		t.Errorf("expected the SDK rewind error, got: %v", err)
	}
	if tr.called != 1 {
		t.Errorf("expected the retry to abort before a second request reaches the backend, got %d attempts", tr.called)
	}
}
