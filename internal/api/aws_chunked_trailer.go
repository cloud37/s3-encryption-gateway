package api

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	maxAWSTrailerBytes = 64 << 10
	maxAWSTrailerCount = 64
)

func verifyAWSTrailers(b *bufio.Reader, body *os.File, declaration string, signing *V4SigningContext, mode streamingPayloadMode, final [32]byte) error {
	if (mode == streamingSignedPayloadTrailer || mode == streamingUnsignedPayloadTrailer) && declaration == "" {
		return ErrStreamingTrailer
	}
	if mode == streamingSignedPayloadTrailer && (signing == nil || len(signing.signingKey) == 0) {
		return ErrSignatureMismatch
	}
	decl := strings.Split(declaration, ",")
	if len(decl) == 0 || decl[0] == "" || len(decl) > maxAWSTrailerCount {
		return ErrStreamingTrailer
	}
	set := make(map[string]bool)
	forbidden := map[string]bool{"content-length": true, "transfer-encoding": true, "authorization": true, "x-amz-content-sha256": true, "x-amz-trailer": true}
	allowedChecksums := map[string]bool{
		"x-amz-checksum-crc32":  true,
		"x-amz-checksum-crc32c": true,
		"x-amz-checksum-sha1":   true,
		"x-amz-checksum-sha256": true,
	}
	for _, name := range decl {
		if name != strings.ToLower(name) || name == "" || set[name] || forbidden[name] || !allowedChecksums[name] || !validTrailerToken(name) {
			return ErrStreamingTrailer
		}
		set[name] = true
	}
	if mode == streamingSignedPayloadTrailer && len(set) == 0 {
		return ErrStreamingTrailer
	}
	values := make(map[string]string)
	received := make(map[string]bool)
	var used int
	for {
		line, err := readAWSLine(b, maxAWSTrailerBytes-used)
		if err != nil || len(line) > maxAWSTrailerBytes-used {
			return ErrStreamingTrailer
		}
		used += len(line)
		if line == "\r\n" {
			break
		}
		if len(line) < 3 || !strings.HasSuffix(line, "\r\n") {
			return ErrStreamingTrailer
		}
		parts := strings.SplitN(strings.TrimSuffix(line, "\r\n"), ":", 2)
		if len(parts) != 2 || (!set[parts[0]] && !(mode == streamingSignedPayloadTrailer && parts[0] == "x-amz-trailer-signature")) || received[parts[0]] {
			return ErrStreamingTrailer
		}
		if parts[0] != strings.ToLower(parts[0]) || !validTrailerToken(parts[0]) {
			return ErrStreamingTrailer
		}
		value := strings.TrimSpace(parts[1])
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return ErrStreamingTrailer
		}
		values[parts[0]] = value
		received[parts[0]] = true
	}
	if len(received) != len(set)+boolInt(mode == streamingSignedPayloadTrailer) {
		return ErrStreamingTrailer
	}
	for name := range set {
		if !received[name] {
			return ErrStreamingTrailer
		}
	}
	if err := verifyTrailerChecksums(body, values); err != nil {
		return err
	}
	if mode == streamingSignedPayloadTrailer {
		sig, ok := values["x-amz-trailer-signature"]
		if !ok || !validLowerHex(sig, 64) {
			return ErrSignatureMismatch
		}
		supplied := make([]byte, 32)
		if _, err := hex.Decode(supplied, []byte(sig)); err != nil {
			return ErrSignatureMismatch
		}
		defer clearAuthBytes(supplied)
		names := make([]string, 0, len(values))
		for name := range values {
			if name != "x-amz-trailer-signature" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		var canon strings.Builder
		for _, name := range names {
			canon.WriteString(name)
			canon.WriteByte(':')
			canon.WriteString(values[name])
			canon.WriteByte('\n')
		}
		hash := sha256.Sum256([]byte(canon.String()))
		input := "AWS4-HMAC-SHA256-TRAILER\n" + signing.timestamp + "\n" + signing.credentialScope + "\n" + hex.EncodeToString(final[:]) + "\n" + hex.EncodeToString(hash[:])
		h := hmac.New(sha256.New, signing.signingKey)
		_, _ = h.Write([]byte(input))
		expected := h.Sum(nil)
		defer clearAuthBytes(expected)
		if !hmac.Equal(expected, supplied) {
			return ErrSignatureMismatch
		}
	} else if _, ok := values["x-amz-trailer-signature"]; ok {
		return ErrStreamingTrailer
	}
	if extra, err := b.ReadByte(); err == nil {
		_ = extra
		return ErrStreamingTrailingData
	} else if err != io.EOF {
		return ErrStreamingTrailingData
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind body after trailer verification: %v", ErrStreamingSpool, err)
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func verifyTrailerChecksums(body *os.File, values map[string]string) error {
	if len(values) == 0 {
		return ErrStreamingTrailer
	}
	checksumCount := 0
	for name := range values {
		if strings.HasPrefix(name, "x-amz-checksum-") {
			checksumCount++
		}
	}
	if checksumCount == 0 {
		return ErrStreamingTrailer
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind body for trailer checksum: %v", ErrStreamingSpool, err)
	}
	var h256 = sha256.New()
	var h1 = sha1.New()
	crc32h := crc32.NewIEEE()
	crc32ch := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	buf := make([]byte, 32<<10)
	for {
		n, readErr := streamingSpoolOps.read(body, buf)
		if n > 0 {
			_, _ = h256.Write(buf[:n])
			_, _ = h1.Write(buf[:n])
			_, _ = crc32h.Write(buf[:n])
			_, _ = crc32ch.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("%w: read body for trailer checksum: %v", ErrStreamingSpool, readErr)
		}
	}
	if v, ok := values["x-amz-checksum-sha256"]; ok {
		want, e := base64.StdEncoding.DecodeString(v)
		got := h256.Sum(nil)
		if e != nil || len(want) != sha256.Size || !hmac.Equal(want, got) {
			return ErrSignatureMismatch
		}
	}
	if v, ok := values["x-amz-checksum-sha1"]; ok {
		want, e := base64.StdEncoding.DecodeString(v)
		got := h1.Sum(nil)
		if e != nil || len(want) != sha1.Size || !hmac.Equal(want, got) {
			return ErrSignatureMismatch
		}
	}
	if v, ok := values["x-amz-checksum-crc32"]; ok {
		want, e := base64.StdEncoding.DecodeString(v)
		got := crc32h.Sum32()
		if e != nil || len(want) != 4 || !hmac.Equal(want, []byte{byte(got >> 24), byte(got >> 16), byte(got >> 8), byte(got)}) {
			return ErrSignatureMismatch
		}
	}
	if v, ok := values["x-amz-checksum-crc32c"]; ok {
		want, e := base64.StdEncoding.DecodeString(v)
		got := crc32ch.Sum32()
		if e != nil || len(want) != 4 || !hmac.Equal(want, []byte{byte(got >> 24), byte(got >> 16), byte(got >> 8), byte(got)}) {
			return ErrSignatureMismatch
		}
	}
	return nil
}

func validTrailerToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
