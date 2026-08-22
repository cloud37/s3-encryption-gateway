package api

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

type verifiedAWSBody interface {
	io.Reader
	io.Seeker
	io.Closer
	DecodedLength() int64
}

// streamingSpoolOps is package-private so failure injection can exercise the
// real temporary-file path without replacing the verifier with a fake.
var streamingSpoolOps = struct {
	createTemp func(string, string) (*os.File, error)
	remove     func(string) error
	chmod      func(*os.File, os.FileMode) error
	close      func(*os.File) error
	read       func(*os.File, []byte) (int, error)
	write      func(*os.File, []byte) (int, error)
	seek       func(*os.File, int64, int) (int64, error)
}{
	createTemp: os.CreateTemp,
	remove:     os.Remove,
	chmod:      func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) },
	close:      func(f *os.File) error { return f.Close() },
	read:       func(f *os.File, p []byte) (int, error) { return f.Read(p) },
	write:      func(f *os.File, p []byte) (int, error) { return f.Write(p) },
	seek:       func(f *os.File, offset int64, whence int) (int64, error) { return f.Seek(offset, whence) },
}

type verifiedAWSFile struct {
	*os.File
	length  int64
	path    string
	closed  bool
	closeMu sync.Mutex
}

func (f *verifiedAWSFile) DecodedLength() int64 { return f.length }
func (f *verifiedAWSFile) Close() error {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	err := streamingSpoolOps.close(f.File)
	removeErr := streamingSpoolOps.remove(f.path)
	if err != nil {
		return fmt.Errorf("%w: close temporary body: %v", ErrStreamingSpool, err)
	}
	if removeErr != nil {
		return fmt.Errorf("%w: remove temporary body: %v", ErrStreamingSpool, removeErr)
	}
	return nil
}

func validAWSContentEncoding(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) != 1 || strings.TrimSpace(parts[0]) != "aws-chunked" {
		return false
	}
	return true
}

func verifyAndSpoolAWSBody(r *http.Request, signing *V4SigningContext) (verifiedAWSBody, error) {
	mode, modeErr := classifyStreamingPayloadMode(r.Header.Get("x-amz-content-sha256"))
	if modeErr != nil {
		return nil, modeErr
	}
	if mode != streamingNone && signing != nil && signing.mode != mode {
		return nil, ErrStreamingFraming
	}
	if signing == nil && (mode == streamingSignedPayload || mode == streamingSignedPayloadTrailer) {
		return nil, ErrSignatureMismatch
	}
	if mode != streamingNone && !validAWSContentEncoding(r.Header.Get("Content-Encoding")) {
		return nil, ErrStreamingFraming
	}
	if mode != streamingNone && len(r.Header.Values("X-Amz-Decoded-Content-Length")) != 1 {
		return nil, ErrStreamingFraming
	}
	decoded := int64(-1)
	if v := r.Header.Get("x-amz-decoded-content-length"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil || parsed < 0 {
			return nil, ErrStreamingFraming
		}
		decoded = parsed
	}
	f, err := streamingSpoolOps.createTemp("", "s3gw-aws-body-*")
	if err != nil {
		return nil, fmt.Errorf("%w: create temporary body: %v", ErrStreamingSpool, err)
	}
	path := f.Name()
	if err := streamingSpoolOps.chmod(f, 0600); err != nil {
		_ = streamingSpoolOps.close(f)
		_ = streamingSpoolOps.remove(path)
		return nil, fmt.Errorf("%w: chmod temporary body: %v", ErrStreamingSpool, err)
	}
	cleanup := func() { _ = streamingSpoolOps.close(f); _ = streamingSpoolOps.remove(path) }
	b := bufio.NewReader(r.Body)
	if r.Context().Err() != nil {
		cleanup()
		return nil, ErrStreamingCanceled
	}
	length, finalSignature, err := verifyAWSChunkedContext(b, f, signing, decoded, mode == streamingSignedPayloadTrailer || mode == streamingUnsignedPayloadTrailer, r.Context().Done())
	// The verifier transfers the final chain signature to this caller because
	// trailer authentication needs it. The caller owns it until that work ends.
	defer clearAuthBytes(finalSignature[:])
	if err != nil {
		cleanup()
		if err == ErrStreamingCanceled || err == ErrIncompleteBody || err == ErrStreamingFraming || err == ErrStreamingLength || err == ErrStreamingTrailer || err == ErrStreamingTrailingData || err == ErrSignatureMismatch {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrStreamingSpool, err)
	}
	if mode == streamingSignedPayloadTrailer || mode == streamingUnsignedPayloadTrailer {
		if err := verifyAWSTrailers(b, f, r.Header.Get("X-Amz-Trailer"), signing, mode, finalSignature); err != nil {
			cleanup()
			return nil, err
		}
	}
	if _, err := streamingSpoolOps.seek(f, 0, io.SeekStart); err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: %v", ErrStreamingSpool, err)
	}
	return &verifiedAWSFile{File: f, length: length, path: path}, nil
}
