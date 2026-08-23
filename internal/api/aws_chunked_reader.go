package api

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strconv"
)

const maxAWSChunkHeaderBytes = 8 << 10

const maxAWSChunkBytes = 64 << 20

// verifyAWSChunked decodes one complete AWS chunked body. It is deliberately
// private: callers must use the verified spool, never a streaming decoder.
func verifyAWSChunked(b *bufio.Reader, dst io.Writer, signing *V4SigningContext, decodedLength int64, trailers bool) (int64, [32]byte, error) {
	return verifyAWSChunkedContext(b, dst, signing, decodedLength, trailers, nil)
}

func verifyAWSChunkedContext(b *bufio.Reader, dst io.Writer, signing *V4SigningContext, decodedLength int64, trailers bool, done <-chan struct{}) (total int64, final [32]byte, err error) {
	var previous [32]byte
	defer func() {
		clearAuthBytes(previous[:])
		if err != nil {
			clearAuthBytes(final[:])
		}
	}()
	if signing != nil {
		signing.closeMu.Lock()
		closed := signing.closed || len(signing.signingKey) == 0
		signing.closeMu.Unlock()
		if closed {
			return 0, final, ErrSignatureMismatch
		}
		previous = signing.seedSignature
	}
	for {
		if done != nil {
			select {
			case <-done:
				return total, previous, ErrStreamingCanceled
			default:
			}
		}
		line, err := readAWSLine(b, maxAWSChunkHeaderBytes)
		if err != nil {
			if err == io.EOF {
				return total, previous, ErrIncompleteBody
			}
			return total, previous, ErrStreamingFraming
		}
		if len(line) < 3 || line[len(line)-2:] != "\r\n" {
			return total, previous, ErrStreamingFraming
		}
		line = line[:len(line)-2]
		sizeText := line
		supplied := ""
		if signing != nil {
			const marker = ";chunk-signature="
			i := indexByteString(line, marker)
			if i < 1 || indexByteString(line[i+len(marker):], ";") >= 0 {
				return total, previous, ErrStreamingFraming
			}
			sizeText, supplied = line[:i], line[i+len(marker):]
			if !validLowerHex(supplied, 64) {
				return total, previous, ErrStreamingFraming
			}
		} else if i := indexByteString(line, ";chunk-signature="); i >= 1 {
			// Authentication is optional at the gateway boundary. Decode the
			// standard signed framing even when no signing context is available;
			// the signature remains verified whenever authentication is enabled.
			if indexByteString(line[i+len(";chunk-signature="):], ";") >= 0 || !validLowerHex(line[i+len(";chunk-signature="):], 64) {
				return total, previous, ErrStreamingFraming
			}
			sizeText = line[:i]
		} else if indexByteString(line, ";") >= 0 {
			return total, previous, ErrStreamingFraming
		}
		if len(sizeText) == 0 || len(sizeText) > 16 {
			return total, previous, ErrStreamingFraming
		}
		if len(sizeText) > 1 && sizeText[0] == '0' {
			return total, previous, ErrStreamingFraming
		}
		if !validLowerHex(sizeText, len(sizeText)) {
			return total, previous, ErrStreamingFraming
		}
		size, err := strconv.ParseUint(sizeText, 16, 64)
		if err != nil {
			return total, previous, ErrStreamingFraming
		}
		if size == 0 {
			if signing != nil {
				if err := verifyChunkSignature(signing, previous, supplied, nil); err != nil {
					return total, previous, err
				}
				_ = decodeSignature(previous[:], supplied)
			}
			if decodedLength >= 0 && total != decodedLength {
				if total < decodedLength {
					return total, previous, ErrIncompleteBody
				}
				return total, previous, ErrStreamingLength
			}
			if !trailers {
				// S3 clients differ on whether they emit the optional final CRLF
				// after the signed zero-size chunk. Accept that exact terminator,
				// but reject every other trailing byte sequence.
				trailing, readErr := b.ReadByte()
				if readErr == io.EOF {
					return total, previous, nil
				}
				if readErr != nil || trailing != '\r' {
					return total, previous, ErrStreamingTrailingData
				}
				lineEnd, readErr := b.ReadByte()
				if readErr != nil || lineEnd != '\n' {
					return total, previous, ErrStreamingTrailingData
				}
				if _, readErr = b.ReadByte(); readErr != io.EOF {
					return total, previous, ErrStreamingTrailingData
				}
			}
			return total, previous, nil
		}
		if size > maxAWSChunkBytes {
			return total, previous, ErrStreamingLength
		}
		if decodedLength >= 0 {
			remaining := decodedLength - total
			if remaining < 0 || size > uint64(remaining) { // #nosec G115 -- remaining is checked non-negative
				return total, previous, ErrStreamingLength
			}
		}
		var dataHash hashWriter
		if signing != nil {
			dataHash.h = sha256.New()
		}
		// Stage the chunk on disk until its signature has been accepted. This
		// keeps untrusted payload out of the final spool and bounds memory for
		// chunks up to the protocol limit.
		chunkFile, err := streamingSpoolOps.createTemp("", "s3gw-aws-chunk-*")
		if err != nil {
			return total, previous, ErrStreamingSpool
		}
		chunkPath := chunkFile.Name()
		cleanupChunk := func() { _ = streamingSpoolOps.close(chunkFile); _ = streamingSpoolOps.remove(chunkPath) }
		if err := streamingSpoolOps.chmod(chunkFile, 0600); err != nil {
			cleanupChunk()
			return total, previous, ErrStreamingSpool
		}
		if err := copyChunk(b, chunkFile, &dataHash, size, done); err != nil {
			cleanupChunk()
			return total, previous, err
		}
		if err := expectCRLF(b); err != nil {
			cleanupChunk()
			return total, previous, ErrStreamingFraming
		}
		if signing != nil {
			if err := verifyChunkSignatureHash(signing, previous, supplied, dataHash.h.Sum(nil)); err != nil {
				cleanupChunk()
				return total, previous, err
			}
			_ = decodeSignature(previous[:], supplied)
		}
		if _, err := streamingSpoolOps.seek(chunkFile, 0, io.SeekStart); err != nil {
			cleanupChunk()
			return total, previous, ErrStreamingSpool
		}
		if err := copySpoolFile(chunkFile, dst); err != nil {
			cleanupChunk()
			return total, previous, ErrStreamingSpool
		}
		cleanupChunk()
		total += int64(size)
	}
}

func copySpoolFile(src *os.File, dst io.Writer) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := streamingSpoolOps.read(src, buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

type hashWriter struct{ h hash.Hash }

func (w *hashWriter) Write(p []byte) (int, error) {
	if w.h == nil {
		return len(p), nil
	}
	return w.h.Write(p)
}

func readAWSLine(r *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > limit {
			return "", ErrStreamingFraming
		}
		if err == nil {
			return string(line), nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}

func copyChunk(r *bufio.Reader, dst io.Writer, hash io.Writer, size uint64, done <-chan struct{}) error {
	buf := make([]byte, 32<<10)
	for size > 0 {
		if done != nil {
			select {
			case <-done:
				return ErrStreamingCanceled
			default:
			}
		}
		n := uint64(len(buf))
		if n > size {
			n = size
		}
		got, err := io.ReadFull(r, buf[:n])
		if got > 0 {
			if hash != nil {
				if _, e := hash.Write(buf[:got]); e != nil {
					return e
				}
			}
			var writeErr error
			if file, ok := dst.(*os.File); ok {
				_, writeErr = streamingSpoolOps.write(file, buf[:got])
			} else {
				_, writeErr = dst.Write(buf[:got])
			}
			if writeErr != nil {
				return writeErr
			}
			size -= uint64(got)
		}
		if err != nil {
			if err == context.Canceled {
				return ErrStreamingCanceled
			}
			return ErrIncompleteBody
		}
	}
	return nil
}

func validLowerHex(s string, width int) bool {
	if len(s) != width {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
func decodeSignature(dst []byte, s string) error {
	if !validLowerHex(s, 64) || len(dst) != 32 {
		return ErrStreamingFraming
	}
	_, err := hex.Decode(dst, []byte(s))
	return err
}
func indexByteString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func expectCRLF(r *bufio.Reader) error {
	a, e1 := r.ReadByte()
	b, e2 := r.ReadByte()
	if e1 != nil || e2 != nil || a != '\r' || b != '\n' {
		return ErrStreamingFraming
	}
	return nil
}

func verifyChunkSignature(c *V4SigningContext, previous [32]byte, supplied string, data []byte) error {
	h := sha256.Sum256(data)
	return verifyChunkSignatureHash(c, previous, supplied, h[:])
}
func verifyChunkSignatureHash(c *V4SigningContext, previous [32]byte, supplied string, dataHash []byte) error {
	if c == nil || !validLowerHex(supplied, 64) {
		return ErrSignatureMismatch
	}
	c.closeMu.Lock()
	if c.closed || len(c.signingKey) == 0 {
		c.closeMu.Unlock()
		return ErrSignatureMismatch
	}
	key := append([]byte(nil), c.signingKey...)
	timestamp, scope := c.timestamp, c.credentialScope
	c.closeMu.Unlock()
	defer clearAuthBytes(key)
	provided := make([]byte, sha256.Size)
	if _, err := hex.Decode(provided, []byte(supplied)); err != nil {
		clearAuthBytes(provided)
		return ErrSignatureMismatch
	}
	emptyHash := sha256.Sum256(nil)
	input := "AWS4-HMAC-SHA256-PAYLOAD\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(previous[:]) + "\n" + hex.EncodeToString(emptyHash[:]) + "\n" + hex.EncodeToString(dataHash)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(input))
	expected := h.Sum(nil)
	defer clearAuthBytes(provided)
	defer clearAuthBytes(expected)
	if !hmac.Equal(expected, provided) {
		return ErrSignatureMismatch
	}
	return nil
}
