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
		if r.Body != nil && !strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") {
			r.Body = &countingReadCloser{ReadCloser: r.Body, onRead: func(n int64) {
				if h.metrics != nil {
					h.metrics.RecordS3ClientBytes(r.Context(), bucket, "in", n)
				}
			}}
		}
		defer func() {
			if h.metrics != nil {
				h.metrics.RecordS3ClientRequest(r.Context(), op, bucket, recorder.StatusCode())
				h.metrics.RecordS3ClientBytes(r.Context(), bucket, "out", recorder.BytesWritten())
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

func (h *Handler) instrumentS3(operation string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := mux.Vars(r)["bucket"]
		recorder := &s3ResponseRecorder{ResponseWriter: w}
		if r.Body != nil && !strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") {
			r.Body = &countingReadCloser{ReadCloser: r.Body, onRead: func(n int64) {
				if h.metrics != nil {
					h.metrics.RecordS3ClientBytes(r.Context(), bucket, "in", n)
				}
			}}
		}
		defer func() {
			if h.metrics != nil {
				h.metrics.RecordS3ClientRequest(r.Context(), operation, bucket, recorder.StatusCode())
				h.metrics.RecordS3ClientBytes(r.Context(), bucket, "out", recorder.BytesWritten())
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

type countingReadCloser struct {
	io.ReadCloser
	onRead func(int64)
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 && r.onRead != nil {
		r.onRead(int64(n))
	}
	return n, err
}

func s3OperationName(r *http.Request) string {
	q := r.URL.Query()
	key := mux.Vars(r)["key"] != "" && strings.Contains(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.URL.Path == "/" {
		return "ListBuckets"
	}
	if r.Method == http.MethodOptions {
		return "CORSPreflight"
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" && key && r.Method == http.MethodPut {
		if _, ok := q["partNumber"]; ok {
			return "UploadPartCopy"
		}
		return "CopyObject"
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
	if _, ok := q["partNumber"]; ok {
		return "UploadPart"
	}
	if _, ok := q["uploads"]; ok {
		if key && r.Method == http.MethodPost {
			return "CreateMultipartUpload"
		}
		if !key && r.Method == http.MethodGet {
			return "ListMultipartUploads"
		}
	}
	if key {
		for _, item := range []struct{ query, get, put, del string }{
			{"retention", "GetObjectRetention", "PutObjectRetention", ""},
			{"legal-hold", "GetObjectLegalHold", "PutObjectLegalHold", ""},
			{"tagging", "GetObjectTagging", "PutObjectTagging", "DeleteObjectTagging"},
			{"acl", "GetObjectACL", "PutObjectACL", ""},
		} {
			if _, ok := q[item.query]; ok {
				switch r.Method {
				case http.MethodGet:
					return item.get
				case http.MethodPut:
					return item.put
				case http.MethodDelete:
					return item.del
				}
			}
		}
		if _, ok := q["restore"]; ok {
			return "RestoreObject"
		}
		if _, ok := q["select"]; ok {
			return "SelectObjectContent"
		}
		if _, ok := q["select-type"]; ok {
			return "SelectObjectContent"
		}
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
	for _, item := range []struct{ query, get, put, del string }{
		{"object-lock", "GetObjectLockConfiguration", "PutObjectLockConfiguration", ""},
		{"lifecycle", "GetBucketLifecycle", "PutBucketLifecycle", "DeleteBucketLifecycle"},
		{"policy", "GetBucketPolicy", "PutBucketPolicy", "DeleteBucketPolicy"},
		{"cors", "GetBucketCors", "PutBucketCors", "DeleteBucketCors"},
		{"versioning", "GetBucketVersioning", "PutBucketVersioning", ""},
		{"encryption", "GetBucketEncryption", "PutBucketEncryption", "DeleteBucketEncryption"},
		{"acl", "GetBucketACL", "PutBucketACL", ""}, {"location", "GetBucketLocation", "", ""},
		{"notification", "GetBucketNotification", "PutBucketNotification", ""},
		{"replication", "GetBucketReplication", "PutBucketReplication", "DeleteBucketReplication"},
		{"logging", "GetBucketLogging", "PutBucketLogging", ""}, {"requestPayment", "GetBucketRequestPayment", "PutBucketRequestPayment", ""},
		{"website", "GetBucketWebsite", "PutBucketWebsite", "DeleteBucketWebsite"},
		{"inventory", "GetBucketInventory", "PutBucketInventory", "DeleteBucketInventory"},
		{"analytics", "GetBucketAnalytics", "", ""}, {"intelligent-tiering", "", "PutBucketIntelligentTiering", ""},
	} {
		if _, ok := q[item.query]; ok {
			switch r.Method {
			case http.MethodGet:
				return item.get
			case http.MethodPut:
				return item.put
			case http.MethodDelete:
				return item.del
			}
		}
	}
	if _, ok := q["delete"]; ok {
		return "DeleteObjects"
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
