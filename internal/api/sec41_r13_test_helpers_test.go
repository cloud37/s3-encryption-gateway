package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sec41AuthChunkedRequest is deliberately independent of the production
// canonical-request and signing functions. It exercises AuthMiddleware before
// the body verifier obtains its context.
func sec41AuthChunkedRequest(method, rawURL string, payload [][]byte, bad int) *http.Request {
	total := 0
	for _, p := range payload {
		total += len(p)
	}
	return sec41AuthChunkedRequestWithLength(method, rawURL, payload, bad, total)
}

func sec41AuthChunkedRequestWithLength(method, rawURL string, payload [][]byte, bad int, decodedLength int) *http.Request {
	access, secret := "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	now := time.Now().UTC()
	timestamp, date := now.Format("20060102T150405Z"), now.Format("20060102")
	scope := date + "/us-east-1/s3/aws4_request"
	seed := sec41SigV4RequestSignatureWithLength(method, rawURL, timestamp, access, secret, scope, decodedLength)
	key := sec41SigningKey(secret, date, "us-east-1", "s3")
	var body strings.Builder
	previous := seed
	for i, part := range payload {
		sig := sec41ChunkSignature(key, timestamp, scope, previous, part)
		if i == bad {
			sig[0] ^= 1
		}
		sec41FormatChunk(&body, part, sig)
		previous = sec41ChunkSignature(key, timestamp, scope, previous, part)
	}
	zero := sec41ChunkSignature(key, timestamp, scope, previous, nil)
	if bad == len(payload) {
		zero[0] ^= 1
	}
	sec41FormatChunk(&body, nil, zero)

	r := httptest.NewRequest(method, rawURL, strings.NewReader(body.String()))
	r.Host = "localhost"
	r.Header.Set("Host", r.Host)
	r.Header.Set("X-Amz-Date", timestamp)
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(decodedLength))
	signed := []string{"content-encoding", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-decoded-content-length"}
	canonical := sec41CanonicalRequest(r, signed)
	hash := sec41Hash([]byte(canonical))
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	authSig := sec41HMAC(key, []byte(stringToSign))
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", access, scope, strings.Join(signed, ";"), hex.EncodeToString(authSig[:])))
	return r
}

func sec41SigV4RequestSignature(method, rawURL, timestamp, access, secret, scope string) [32]byte {
	return sec41SigV4RequestSignatureWithLength(method, rawURL, timestamp, access, secret, scope, 16)
}

func sec41SigV4RequestSignatureWithLength(method, rawURL, timestamp, access, secret, scope string, decodedLength int) [32]byte {
	r := httptest.NewRequest(method, rawURL, nil)
	r.Host = "localhost"
	r.Header.Set("Host", r.Host)
	r.Header.Set("X-Amz-Date", timestamp)
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(decodedLength))
	signed := []string{"content-encoding", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-decoded-content-length"}
	canonical := sec41CanonicalRequest(r, signed)
	key := sec41SigningKey(secret, scope[:8], "us-east-1", "s3")
	hash := sec41Hash([]byte(canonical))
	return sec41HMAC(key, []byte("AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(hash[:])))
}

func sec41CanonicalRequest(r *http.Request, signed []string) string {
	q := r.URL.Query()
	var query []string
	for k, values := range q {
		for _, v := range values {
			query = append(query, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	sort.Strings(query)
	var headers strings.Builder
	for _, name := range signed {
		headers.WriteString(name)
		headers.WriteByte(':')
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		headers.WriteString(strings.TrimSpace(value))
		headers.WriteByte('\n')
	}
	payload := r.Header.Get("x-amz-content-sha256")
	return r.Method + "\n" + r.URL.EscapedPath() + "\n" + strings.Join(query, "&") + "\n" + headers.String() + "\n" + strings.Join(signed, ";") + "\n" + payload
}

func sec41Hash(data []byte) [32]byte { return sha256.Sum256(data) }
func sec41HMAC(key, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func sec41SigningKey(secret, date, region, service string) []byte {
	k := sec41HMAC([]byte("AWS4"+secret), []byte(date))
	k2 := sec41HMAC(k[:], []byte(region))
	k3 := sec41HMAC(k2[:], []byte(service))
	k4 := sec41HMAC(k3[:], []byte("aws4_request"))
	return k4[:]
}
func sec41ChunkSignature(key []byte, timestamp, scope string, previous [32]byte, data []byte) [32]byte {
	d := sha256.Sum256(data)
	e := sha256.Sum256(nil)
	return sec41HMAC(key, []byte("AWS4-HMAC-SHA256-PAYLOAD\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(previous[:])+"\n"+hex.EncodeToString(e[:])+"\n"+hex.EncodeToString(d[:])))
}
func sec41FormatChunk(b *strings.Builder, data []byte, sig [32]byte) {
	fmt.Fprintf(b, "%x;chunk-signature=%s\r\n", len(data), hex.EncodeToString(sig[:]))
	if len(data) > 0 {
		b.Write(data)
		b.WriteString("\r\n")
	}
}

func sec41AuthedRouter(h http.Handler) http.Handler {
	return AuthMiddleware(testCredentialStore(), 5*time.Minute, logrusTestLogger(), nil, true)(h)
}

// sec41AuthRequestBody signs the headers independently of the wire body. The
// caller can therefore mutate physical framing after authentication without
// accidentally turning the test into an authentication test.
func sec41AuthRequestBody(method, rawURL, mode, body string, decoded int, trailer string) *http.Request {
	access, secret := "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	now := time.Now().UTC()
	timestamp, date := now.Format("20060102T150405Z"), now.Format("20060102")
	scope := date + "/us-east-1/s3/aws4_request"
	r := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	r.Host = "localhost"
	r.Header.Set("Host", r.Host)
	r.Header.Set("X-Amz-Date", timestamp)
	r.Header.Set("X-Amz-Content-Sha256", mode)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(decoded))
	if trailer != "" {
		r.Header.Set("X-Amz-Trailer", trailer)
	}
	signed := []string{"content-encoding", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-decoded-content-length"}
	canonical := sec41CanonicalRequest(r, signed)
	hash := sec41Hash([]byte(canonical))
	key := sec41SigningKey(secret, date, "us-east-1", "s3")
	authSig := sec41HMAC(key, []byte("AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(hash[:])))
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", access, scope, strings.Join(signed, ";"), hex.EncodeToString(authSig[:])))
	return r
}

// sec41AuthSignedTrailerRequest builds the wire body and signs only the HTTP
// request headers here. The trailer signature is deliberately calculated in
// this test helper rather than through production signing code.
func sec41AuthSignedTrailerRequest(method, rawURL string, payload []byte, badChecksum, badHMAC bool) *http.Request {
	if badChecksum {
		bad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-sha256: %s\r\n\r\n", len(payload), payload, bad)
		return sec41AuthRequestBody(method, rawURL, "STREAMING-UNSIGNED-PAYLOAD-TRAILER", body, len(payload), "x-amz-checksum-sha256")
	}
	_, secret := "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	// Use the independent header signer, then replace only the wire body.
	r := sec41AuthRequestBody(method, rawURL, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "", len(payload), "x-amz-checksum-sha256")
	timestamp := r.Header.Get("X-Amz-Date")
	date := timestamp[:8]
	scope := date + "/us-east-1/s3/aws4_request"
	key := sec41SigningKey(secret, date, "us-east-1", "s3")
	auth := r.Header.Get("Authorization")
	seedText := auth[strings.LastIndex(auth, "Signature=")+len("Signature="):]
	seedBytes, err := hex.DecodeString(seedText)
	if err != nil {
		panic(err)
	}
	var seed [32]byte
	copy(seed[:], seedBytes)

	chunkSig := sec41ChunkSignature(key, timestamp, scope, seed, payload)
	zeroSig := sec41ChunkSignature(key, timestamp, scope, chunkSig, nil)
	digest := sha256.Sum256(payload)
	trailerValue := base64.StdEncoding.EncodeToString(digest[:])
	if badChecksum {
		trailerValue = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))
	}
	trailerHash := sha256.Sum256([]byte("x-amz-checksum-sha256:" + trailerValue + "\n"))
	trailerSig := sec41HMAC(key, []byte("AWS4-HMAC-SHA256-TRAILER\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(zeroSig[:])+"\n"+hex.EncodeToString(trailerHash[:])))
	if badHMAC {
		trailerSig[0] ^= 1
	}
	var body strings.Builder
	sec41FormatChunk(&body, payload, chunkSig)
	sec41FormatChunk(&body, nil, zeroSig)
	fmt.Fprintf(&body, "x-amz-checksum-sha256: %s\r\nx-amz-trailer-signature: %s\r\n\r\n", trailerValue, hex.EncodeToString(trailerSig[:]))
	r.Body = io.NopCloser(strings.NewReader(body.String()))
	return r
}

func logrusTestLogger() *logrus.Logger { l := logrus.New(); l.SetOutput(io.Discard); return l }
