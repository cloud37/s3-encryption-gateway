package api

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// s3ResponseRecorder records the committed response status and bytes written
// without changing the ResponseWriter contract used by S3 streaming handlers.
type s3ResponseRecorder struct {
	http.ResponseWriter
	status       int
	wroteHeader  bool
	bytesWritten int64
}

func (w *s3ResponseRecorder) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *s3ResponseRecorder) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.bytesWritten += int64(n)
	}
	return n, err
}

func (w *s3ResponseRecorder) StatusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *s3ResponseRecorder) BytesWritten() int64         { return w.bytesWritten }
func (w *s3ResponseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *s3ResponseRecorder) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *s3ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *s3ResponseRecorder) Push(target string, opts *http.PushOptions) error {
	p, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

func (w *s3ResponseRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		if n > 0 {
			w.bytesWritten += n
		}
		return n, err
	}
	n, err := io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
	if n > 0 {
		w.bytesWritten += n
	}
	return n, err
}

// clientByteReader counts bytes actually consumed by a handler.
// instrumentedBody is kept concrete so it can call the metrics API without
// exposing metrics internals through the API package.
type clientInputReader struct {
	r      io.Reader
	onRead func(int64)
}

func (r *clientInputReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 && r.onRead != nil {
		r.onRead(int64(n))
	}
	return n, err
}

func (h *Handler) s3InstrumentationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := mux.Vars(r)["bucket"]
		op := s3OperationName(r)
		recorder := &s3ResponseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if h.metrics != nil {
			h.metrics.RecordS3ClientRequest(r.Context(), op, bucket, recorder.StatusCode())
			h.metrics.RecordS3ClientBytes(r.Context(), bucket, "out", recorder.BytesWritten())
		}
	})
}

func (h *Handler) instrumentS3(operation string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := mux.Vars(r)["bucket"]
		recorder := &s3ResponseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if h.metrics != nil {
			h.metrics.RecordS3ClientRequest(r.Context(), operation, bucket, recorder.StatusCode())
			h.metrics.RecordS3ClientBytes(r.Context(), bucket, "out", recorder.BytesWritten())
		}
	})
}

func s3OperationName(r *http.Request) string {
	q := r.URL.Query()
	for _, item := range []struct{ key, op string }{
		{"partNumber", "UploadPart"}, {"uploads", "CreateMultipartUpload"},
		{"delete", "DeleteObjects"}, {"tagging", "ObjectTagging"}, {"acl", "ACL"}, {"retention", "ObjectRetention"},
		{"legal-hold", "ObjectLegalHold"}, {"object-lock", "ObjectLock"}, {"lifecycle", "BucketLifecycle"},
		{"policy", "BucketPolicy"}, {"cors", "BucketCORS"}, {"versioning", "BucketVersioning"},
		{"encryption", "BucketEncryption"}, {"location", "GetBucketLocation"}, {"notification", "BucketNotification"},
		{"replication", "BucketReplication"}, {"logging", "BucketLogging"}, {"requestPayment", "BucketRequestPayment"},
		{"website", "BucketWebsite"}, {"inventory", "BucketInventory"}, {"analytics", "BucketAnalytics"},
		{"intelligent-tiering", "BucketIntelligentTiering"}, {"restore", "RestoreObject"}, {"select", "SelectObjectContent"},
	} {
		if _, ok := q[item.key]; ok {
			return item.op
		}
	}
	if _, ok := q["uploadId"]; ok {
		switch r.Method {
		case http.MethodGet:
			return "ListParts"
		case http.MethodPost:
			return "CompleteMultipartUpload"
		case http.MethodDelete:
			return "AbortMultipartUpload"
		}
	}
	if r.URL.Path == "/" {
		return "ListBuckets"
	}
	if mux.Vars(r)["key"] != "" {
		switch r.Method {
		case http.MethodGet:
			return "GetObject"
		case http.MethodPut:
			return "PutObject"
		case http.MethodDelete:
			return "DeleteObject"
		case http.MethodHead:
			return "HeadObject"
		}
	}
	switch r.Method {
	case http.MethodGet:
		return "ListObjects"
	case http.MethodPut:
		return "CreateBucket"
	case http.MethodDelete:
		return "DeleteBucket"
	case http.MethodHead:
		return "HeadBucket"
	}
	return strings.ToUpper(r.Method) + "S3Request"
}

var _ http.Flusher = (*s3ResponseRecorder)(nil)
var _ http.Hijacker = (*s3ResponseRecorder)(nil)
var _ http.Pusher = (*s3ResponseRecorder)(nil)
var _ io.ReaderFrom = (*s3ResponseRecorder)(nil)
