package api

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
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
	createTemp      func(string, string) (*os.File, error)
	remove          func(string) error
	chmod           func(*os.File, os.FileMode) error
	close           func(*os.File) error
	read            func(*os.File, []byte) (int, error)
	readRequestBody func(io.Reader, []byte) (int, error)
	write           func(*os.File, []byte) (int, error)
	seek            func(*os.File, int64, int) (int64, error)
}{
	createTemp:      os.CreateTemp,
	remove:          os.Remove,
	chmod:           func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) },
	close:           func(f *os.File) error { return f.Close() },
	read:            func(f *os.File, p []byte) (int, error) { return f.Read(p) },
	readRequestBody: func(r io.Reader, p []byte) (int, error) { return r.Read(p) },
	write:           func(f *os.File, p []byte) (int, error) { return f.Write(p) },
	seek:            func(f *os.File, offset int64, whence int) (int64, error) { return f.Seek(offset, whence) },
}

type verifiedAWSFile struct {
	*os.File
	length      int64
	path        string
	closed      bool
	closeMu     sync.Mutex
	reservation SpoolReservation
}

func (f *verifiedAWSFile) DecodedLength() int64 { return f.length }
func (f *verifiedAWSFile) Close() error {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.reservation != nil {
		defer f.reservation.Release()
	}
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

func verifyAndSpoolAWSBody(r *http.Request, signing *V4SigningContext, options ...interface{}) (verifiedAWSBody, error) {
	manager, limit := spoolOptions(options...)
	mode, modeErr := classifyStreamingPayloadMode(r.Header.Get("x-amz-content-sha256"))
	if modeErr != nil {
		return nil, modeErr
	}
	if mode != streamingNone && signing != nil && signing.mode != mode {
		return nil, ErrStreamingFraming
	}
	// Gateways without configured client authentication still need to accept
	// standard SigV4 streaming framing from compatible S3 clients. In that mode
	// there is no client secret with which to verify the chunk chain; the parser
	// still validates framing and decoded length. When authentication is enabled,
	// signing is non-nil and every chunk remains authenticated below.
	// Some unauthenticated S3 clients omit Content-Encoding while still sending
	// correctly framed signed streaming payloads. Header-authenticated requests
	// remain strict because AuthMiddleware validates their full signed header set.
	if mode != streamingNone && !validAWSContentEncoding(r.Header.Get("Content-Encoding")) && !(signing == nil && r.Header.Get("Content-Encoding") == "") {
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
	reservation, err := manager.Acquire(r.Context(), max64(decoded, 0), limit)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrStreamingCanceled
		}
		return nil, err
	}
	directory := ""
	if sm, ok := manager.(*spoolManager); ok {
		directory = sm.tempDirectory()
	}
	f, err := streamingSpoolOps.createTemp(directory, "s3gw-aws-body-*")
	if err != nil {
		reservation.Release()
		return nil, fmt.Errorf("%w: create temporary body: %v", ErrStreamingSpool, err)
	}
	path := f.Name()
	if err := streamingSpoolOps.chmod(f, 0600); err != nil {
		_ = streamingSpoolOps.close(f)
		_ = streamingSpoolOps.remove(path)
		reservation.Release()
		return nil, fmt.Errorf("%w: chmod temporary body: %v", ErrStreamingSpool, err)
	}
	cleanup := func() { _ = streamingSpoolOps.close(f); _ = streamingSpoolOps.remove(path); reservation.Release() }
	b := bufio.NewReader(r.Body)
	if r.Context().Err() != nil {
		cleanup()
		return nil, ErrStreamingCanceled
	}
	writer := &reservingWriter{w: f, reservation: reservation, remaining: max64(decoded, 0)}
	length, finalSignature, err := verifyAWSChunkedContext(b, writer, signing, decoded, mode == streamingSignedPayloadTrailer || mode == streamingUnsignedPayloadTrailer, r.Context().Done())
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
	if decoded < 0 && length > 0 { /* growth is performed by the writer below */
	}
	return &verifiedAWSFile{File: f, length: length, path: path, reservation: reservation}, nil
}

func verifyAndSpoolV4Payload(r *http.Request, signing *V4SigningContext, options ...interface{}) (verifiedAWSBody, error) {
	if r == nil || signing == nil || !signing.verifyPayload {
		return nil, errors.New("invalid concrete SigV4 payload verification request")
	}
	defer r.Body.Close()
	manager, limit := spoolOptions(options...)
	declared := r.ContentLength
	if declared < 0 {
		declared = 0
	}
	reservation, err := manager.Acquire(r.Context(), declared, limit)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrStreamingCanceled
		}
		return nil, err
	}
	directory := ""
	if sm, ok := manager.(*spoolManager); ok {
		directory = sm.tempDirectory()
	}
	f, err := streamingSpoolOps.createTemp(directory, "s3gw-aws-body-*")
	if err != nil {
		reservation.Release()
		return nil, fmt.Errorf("%w: create temporary body: %v", ErrStreamingSpool, err)
	}
	path := f.Name()
	cleanup := func() {
		_ = streamingSpoolOps.close(f)
		_ = streamingSpoolOps.remove(path)
		reservation.Release()
	}
	if err := streamingSpoolOps.chmod(f, 0600); err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: chmod temporary body: %v", ErrStreamingSpool, err)
	}
	hash := sha256.New()
	buf := make([]byte, 32*1024)
	var length int64
	for {
		if err := r.Context().Err(); err != nil {
			cleanup()
			return nil, ErrStreamingCanceled
		}
		n, readErr := streamingSpoolOps.readRequestBody(r.Body, buf)
		if n > 0 {
			extra := int64(n) - declared
			if extra > 0 {
				if err := reservation.Grow(extra); err != nil {
					cleanup()
					return nil, err
				}
			}
			if declared > int64(n) {
				declared -= int64(n)
			} else {
				declared = 0
			}
			written, writeErr := streamingSpoolOps.write(f, buf[:n])
			if written != n || writeErr != nil {
				cleanup()
				return nil, fmt.Errorf("%w: write temporary body", ErrStreamingSpool)
			}
			if _, hashErr := hash.Write(buf[:n]); hashErr != nil {
				cleanup()
				return nil, fmt.Errorf("%w: hash request body", ErrStreamingSpool)
			}
			length += int64(n)
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			cleanup()
			return nil, fmt.Errorf("%w: read request body", ErrStreamingSpool)
		}
	}
	if !hmac.Equal(hash.Sum(nil), signing.expectedPayloadHash[:]) {
		cleanup()
		return nil, ErrSignatureMismatch
	}
	if _, err := streamingSpoolOps.seek(f, 0, io.SeekStart); err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: seek temporary body", ErrStreamingSpool)
	}
	return &verifiedAWSFile{File: f, length: length, path: path, reservation: reservation}, nil
}

func spoolOptions(options ...interface{}) (SpoolManager, int64) {
	m := DefaultSpoolManager()
	limit := int64(5 << 30)
	for _, option := range options {
		switch v := option.(type) {
		case SpoolManager:
			m = v
		case int64:
			limit = v
		case SpoolLimits:
			limit = v.Global
		case *SpoolLimitSource:
			limits := v.Limits()
			limit = limits.Global
		}
	}
	return m, limit
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
