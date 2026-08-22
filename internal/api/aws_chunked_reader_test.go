package api

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The fixture directory is immutable test input. Hashes below make accidental
// replacement with a generated or truncated vector visible in review/tests.
//
//go:embed testdata/sigv4-streaming/*
var sec41StreamingFixtures embed.FS

func TestClassifyStreamingPayloadMode_ClosedSet(t *testing.T) {
	tests := []struct {
		value string
		mode  streamingPayloadMode
		ok    bool
	}{
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", streamingSignedPayload, true},
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", streamingSignedPayloadTrailer, true},
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", streamingUnsignedPayloadTrailer, true},
		{"", streamingNone, true}, {"UNSIGNED-PAYLOAD", streamingNone, true},
		{strings.Repeat("a", 64), streamingNone, true},
		{"streaming-aws4-hmac-sha256-payload", streamingNone, false},
		{"STREAMING-AWS4-HMAC-SHA256-EVENTS", streamingNone, false},
	}
	for _, tt := range tests {
		mode, err := classifyStreamingPayloadMode(tt.value)
		if (err == nil) != tt.ok || mode != tt.mode {
			t.Errorf("classify(%q) = %v, %v; want %v, ok=%v", tt.value, mode, err, tt.mode, tt.ok)
		}
	}
}

func TestSEC41StreamingFixtures_ImmutableAndLoadable(t *testing.T) {
	want := map[string]string{
		"signed-payload.body":   "0cbe7a4aaf83baaaef9eeb68f23e1a1bd12410a7e9719027f1345169dba32752",
		"signed-trailer.body":   "f5319a84be1022e98f78490d57cc49ec8bf333dcd17fd37387c88bf1f94d0ea2",
		"unsigned-trailer.body": "f52cb73b8102c8f926c0c09b28222956d7216db055b16f79574132b2d994d8fc",
		"tampered-chunk.body":   "307ed41f6c663a25a84eb59e378f1b40704b0f4bf962d3d548baa79aa5b5d12b",
		"tampered-zero.body":    "8bb6d82ea12f1ea9e64a162d274c10016a458032a92847196a7e0621eb378b47",
		"tampered-trailer.body": "35da4e516dcb1d1a0bc6b28fd44446ef1fb87351d21c08fb62f9402c8002602a",
		"malformed-crlf.body":   "79b7580221e51a4f2d6ac6a68960bec43d585d987edcddd8c0e1f89daf257641",
		"length-mismatch.body":  "ed2d4b8e59cb8a235da6ba46bbf3d907de9ad58f642c95b26d1cf03aea6e44e6",
		"trailing-bytes.body":   "1128ac2fb63ea1bbccc6d03d21dceb63dd8365473861b3084f9e61b4b52c79cf",
	}
	for name, expected := range want {
		data, err := sec41StreamingFixtures.ReadFile("testdata/sigv4-streaming/" + name)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		if got := hex.EncodeToString(h[:]); got != expected {
			t.Fatalf("%s hash %s", name, got)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

func TestSEC41StreamingFixtures_ExecuteActualBytes(t *testing.T) {
	manifest, err := sec41StreamingFixtures.ReadFile("testdata/sigv4-streaming/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(manifest, &metadata); err != nil {
		t.Fatalf("manifest JSON: %v", err)
	}
	type fixtureManifest struct {
		Mode            string `json:"mode"`
		SigningKey      string `json:"signing_key"`
		Seed            string `json:"seed"`
		Timestamp       string `json:"timestamp"`
		Scope           string `json:"scope"`
		DeclaredTrailer string `json:"declared_trailer"`
		DecodedLength   int64  `json:"decoded_length"`
		Tampering       string `json:"tampering"`
	}
	entries := make(map[string]fixtureManifest)
	for name, raw := range metadata {
		if name == "provenance" {
			continue
		}
		var entry fixtureManifest
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("manifest entry %q: %v", name, err)
		}
		entries[name] = entry
	}
	for _, name := range []string{"signed-payload.body", "signed-trailer.body", "tampered-chunk.body", "tampered-zero.body", "tampered-trailer.body", "unsigned-trailer.body", "malformed-crlf.body", "length-mismatch.body", "trailing-bytes.body"} {
		var entry struct {
			Mode            string `json:"mode"`
			SigningKey      string `json:"signing_key"`
			Seed            string `json:"seed"`
			Timestamp       string `json:"timestamp"`
			Scope           string `json:"scope"`
			DeclaredTrailer string `json:"declared_trailer"`
			DecodedLength   int64  `json:"decoded_length"`
		}
		raw, ok := metadata[name]
		if !ok || json.Unmarshal(raw, &entry) != nil || entry.Mode == "" || entry.DecodedLength < 0 || (strings.Contains(entry.Mode, "HMAC") && (entry.SigningKey == "" || entry.Seed == "" || entry.Timestamp == "" || entry.Scope == "")) {
			t.Fatalf("manifest entry %q is incomplete", name)
		}
	}
	var provenance string
	if err := json.Unmarshal(metadata["provenance"], &provenance); err != nil || provenance != "Local protocol conformance fixtures, not AWS-provided vectors. Every body is a literal CRLF-delimited wire fixture; tampering states describe the mutation present in that file, and none are generated at test runtime." {
		t.Fatalf("manifest provenance mismatch: %q", provenance)
	}
	for _, tc := range []struct {
		name string
		want error
	}{
		{"signed-payload.body", nil}, {"signed-trailer.body", nil},
		{"tampered-chunk.body", ErrSignatureMismatch}, {"tampered-zero.body", ErrSignatureMismatch}, {"tampered-trailer.body", ErrSignatureMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := sec41StreamingFixtures.ReadFile("testdata/sigv4-streaming/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			entry := entries[tc.name]
			mode, err := classifyStreamingPayloadMode(entry.Mode)
			if err != nil {
				t.Fatal(err)
			}
			seedText := strings.TrimSuffix(strings.TrimPrefix(entry.Seed, "sha256("), ")")
			if entry.Seed != "" && seedText == entry.Seed {
				t.Fatalf("malformed seed declaration %q", entry.Seed)
			}
			seed := sha256.Sum256([]byte(seedText))
			c := &V4SigningContext{timestamp: entry.Timestamp, credentialScope: entry.Scope, signingKey: []byte(entry.SigningKey), seedSignature: seed, mode: mode}
			defer c.Close()
			var out bytes.Buffer
			var got error
			trailers := mode == streamingSignedPayloadTrailer || mode == streamingUnsignedPayloadTrailer
			if trailers {
				r := httptest.NewRequest(http.MethodPut, "http://fixture.test", bytes.NewReader(data))
				r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
				r.Header.Set("Content-Encoding", "aws-chunked")
				r.Header.Set("X-Amz-Decoded-Content-Length", strconv.FormatInt(entry.DecodedLength, 10))
				r.Header.Set("X-Amz-Trailer", entry.DeclaredTrailer)
				spool, err := verifyAndSpoolAWSBody(r, c)
				if err == nil {
					defer spool.Close()
					decoded, readErr := io.ReadAll(spool)
					out.Write(decoded)
					got = readErr
				} else {
					got = err
				}
			} else {
				_, _, got = verifyAWSChunked(bufio.NewReader(bytes.NewReader(data)), &out, c, entry.DecodedLength, false)
			}
			if strings.Contains(entry.Tampering, "CRLF") && !bytes.Contains(data, []byte("\n")) {
				// The declaration must describe an actual wire mutation, not a label.
				t.Fatalf("%s declares CRLF tampering but contains no CRLF delimiter", tc.name)
			}
			if !strings.Contains(entry.Tampering, "CRLF") && bytes.Contains(data, []byte("\n")) {
				for i, b := range data {
					if b == '\n' && (i == 0 || data[i-1] != '\r') {
						t.Fatalf("%s contains undeclared bare LF", tc.name)
					}
				}
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("fixture verification error = %v, want %v; decoded=%q", got, tc.want, out.Bytes())
			}
			if tc.want == nil && out.String() != "one" {
				t.Fatalf("valid fixture decoded %q", out.Bytes())
			}
			if tc.name == "tampered-chunk.body" && out.Len() != 0 {
				t.Fatalf("framing-invalid fixture emitted output: %q", out.Bytes())
			}
		})
	}
}

func TestAWSChunkedVerifier_DecodedLengthAndEOF(t *testing.T) {
	for name, input := range map[string]string{
		"underflow":      "3\r\nabc\r\n0\r\n",
		"trailing CR":    "3\r\nabc\r\n0\r\n\r",
		"trailing LF":    "3\r\nabc\r\n0\r\n\n",
		"trailing space": "3\r\nabc\r\n0\r\n ",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(input)), &out, nil, 4, false)
			if err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func FuzzAWSChunkedVerifier(f *testing.F) {
	f.Add([]byte("3\r\nabc\r\n0\r\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var out bytes.Buffer
		_, _, _ = verifyAWSChunked(bufio.NewReader(bytes.NewReader(input)), &out, nil, 1<<20, false)
	})
}

func TestAWSChunkedVerifier_StrictCRLFAndHeaderBounds(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  error
	}{{"bare LF", "3\nabc\n0\r\n", ErrStreamingFraming}, {"unsigned extension", "3;foo=bar\r\nabc\r\n0\r\n", ErrStreamingFraming}, {"empty size", "\r\n", ErrStreamingFraming}, {"nonhex size", "g\r\n", ErrStreamingFraming}, {"signed missing signature", "1;chunk-signature=\r\nx\r\n", ErrStreamingFraming}, {"signed duplicate extension", "1;chunk-signature=" + strings.Repeat("0", 64) + ";chunk-signature=" + strings.Repeat("0", 64) + "\r\nx\r\n", ErrStreamingFraming}, {"signed malformed signature", "1;chunk-signature=" + strings.Repeat("0", 63) + "\r\nx\r\n", ErrStreamingFraming}, {"too large hex", "10000000000000000\r\n", ErrStreamingFraming}, {"missing data CRLF", "1\r\nx", ErrStreamingFraming}, {"zero EOF", "0", ErrIncompleteBody}, {"trailing bytes", "0\r\nextra", ErrStreamingTrailingData}, {"underflow", "3\r\nabc\r\n0\r\n", ErrIncompleteBody}, {"overflow", "3\r\nabc\r\n0\r\n", ErrStreamingLength}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			decoded := int64(-1)
			if tc.name == "underflow" {
				decoded = 4
			}
			if tc.name == "overflow" {
				decoded = 2
			}
			if _, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(tc.input)), &out, func() *V4SigningContext {
				if strings.HasPrefix(tc.name, "signed") {
					return sec41Context()
				}
				return nil
			}(), decoded, false); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
	long := strings.Repeat("a", maxAWSChunkHeaderBytes+1) + "\n"
	if _, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(long)), io.Discard, nil, -1, false); !errors.Is(err, ErrStreamingFraming) {
		t.Fatalf("bounded header error = %v", err)
	}
}

func TestAWSChunkedVerifier_SignedChain(t *testing.T) {
	key := []byte("independent-test-signing-key")
	seed := sha256.Sum256([]byte("seed signature"))
	c := &V4SigningContext{timestamp: "20130524T000000Z", credentialScope: "20130524/us-east-1/s3/aws4_request", signingKey: append([]byte(nil), key...), seedSignature: seed}
	defer c.Close()
	parts := [][]byte{[]byte("first chunk"), []byte("middle chunk"), []byte("final chunk")}
	var body strings.Builder
	previous := seed
	for _, part := range parts {
		sig := independentChunkHMAC(key, c.timestamp, c.credentialScope, previous, part)
		fmtChunk(&body, part, sig)
		previous = sig
	}
	zero := independentChunkHMAC(key, c.timestamp, c.credentialScope, previous, nil)
	fmtChunk(&body, nil, zero)
	var out bytes.Buffer
	got, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(body.String())), &out, c, int64(len("first chunkmiddle chunkfinal chunk")), false)
	if err != nil || got != int64(out.Len()) || out.String() != "first chunkmiddle chunkfinal chunk" {
		t.Fatalf("valid chain: length=%d err=%v body=%q", got, err, out.String())
	}
	for i := range parts {
		mutated := append([]byte(nil), parts[i]...)
		mutated[0] ^= 1
		var bad strings.Builder
		prev := seed
		for j, part := range parts {
			sig := independentChunkHMAC(key, c.timestamp, c.credentialScope, prev, part)
			if j == i {
				part = mutated
			}
			fmtChunk(&bad, part, sig)
			prev = sig
		}
		fmtChunk(&bad, nil, independentChunkHMAC(key, c.timestamp, c.credentialScope, prev, nil))
		var dst bytes.Buffer
		if _, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(bad.String())), &dst, c, int64(len("first chunkmiddle chunkfinal chunk")), false); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	zeroBad := body.String()[:strings.LastIndex(body.String(), "0;")]
	zeroBad += "0;chunk-signature=" + strings.Repeat("0", 64) + "\r\n"
	var dst bytes.Buffer
	if _, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(zeroBad)), &dst, c, int64(len("first chunkmiddle chunkfinal chunk")), false); err == nil {
		t.Fatal("bad zero signature accepted")
	}
}

func TestAWSChunkedVerifier_TrailerDeclarationAndSignature(t *testing.T) {
	data := []byte("trailer payload")
	key := []byte("trailer-independent-key")
	seed := sha256.Sum256([]byte("seed"))
	c := &V4SigningContext{timestamp: "20130524T000000Z", credentialScope: "20130524/us-east-1/s3/aws4_request", signingKey: append([]byte(nil), key...), seedSignature: seed, mode: streamingSignedPayloadTrailer}
	defer c.Close()
	chunk := independentChunkHMAC(key, c.timestamp, c.credentialScope, seed, data)
	zero := independentChunkHMAC(key, c.timestamp, c.credentialScope, chunk, nil)
	h := sha256.Sum256(data)
	trailerValue := base64.StdEncoding.EncodeToString(h[:])
	canonical := "x-amz-checksum-sha256:" + trailerValue + "\n"
	trailerHash := sha256.Sum256([]byte(canonical))
	trailerSig := independentHMAC(key, []byte("AWS4-HMAC-SHA256-TRAILER\n"+c.timestamp+"\n"+c.credentialScope+"\n"+hex.EncodeToString(zero[:])+"\n"+hex.EncodeToString(trailerHash[:])))
	var body strings.Builder
	fmtChunk(&body, data, chunk)
	fmtChunk(&body, nil, zero)
	body.WriteString("x-amz-checksum-sha256: " + trailerValue + "\r\n")
	body.WriteString("x-amz-trailer-signature: " + hex.EncodeToString(trailerSig[:]) + "\r\n\r\n")
	r := httptest.NewRequest(http.MethodPut, "http://example.test/bucket/key", strings.NewReader(body.String()))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
	r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
	spool, err := verifyAndSpoolAWSBody(r, c)
	if err != nil {
		t.Fatalf("%v body=%q", err, body.String())
	}
	defer spool.Close()
	got, _ := io.ReadAll(spool)
	if !bytes.Equal(got, data) {
		t.Fatalf("trailer body=%q", got)
	}
}

func TestAWSTrailerDeclaration_WhitespaceIsRejected(t *testing.T) {
	data := []byte("payload")
	digest := sha256.Sum256(data)
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-sha256: %s\r\n\r\n", len(data), data, base64.StdEncoding.EncodeToString(digest[:]))
	r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader(body))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
	r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256, x-amz-checksum-sha1")
	if _, err := verifyAndSpoolAWSBody(r, nil); err == nil {
		t.Fatal("whitespace-normalized trailer declaration accepted")
	}
}

func TestV4SigningContext_CloseZeroizesKeyAndSeed(t *testing.T) {
	key := []byte("context-key")
	seed := sha256.Sum256([]byte("context-seed"))
	c := &V4SigningContext{signingKey: key, seedSignature: seed}
	c.Close()
	if len(c.signingKey) != 0 || !bytes.Equal(key, make([]byte, len(key))) || c.seedSignature != [32]byte{} {
		t.Fatal("signing context secrets were not zeroized")
	}
}

func TestAWSChunkedVerifier_TrailerChecksums(t *testing.T) {
	data := []byte("all checksum algorithms")
	checks := map[string][]byte{}
	sha256v := sha256.Sum256(data)
	checks["x-amz-checksum-sha256"] = sha256v[:]
	sha1v := sha1.Sum(data)
	checks["x-amz-checksum-sha1"] = sha1v[:]
	crc := crc32.ChecksumIEEE(data)
	checks["x-amz-checksum-crc32"] = []byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)}
	crc = crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
	checks["x-amz-checksum-crc32c"] = []byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)}
	for name, value := range checks {
		t.Run(name, func(t *testing.T) {
			var body strings.Builder
			fmt.Fprintf(&body, "%x\r\n%s\r\n0\r\n", len(data), data)
			body.WriteString(name + ": " + base64.StdEncoding.EncodeToString(value) + "\r\n\r\n")
			r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader(body.String()))
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			r.Header.Set("Content-Encoding", "aws-chunked")
			r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
			r.Header.Set("X-Amz-Trailer", name)
			spool, err := verifyAndSpoolAWSBody(r, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			got, _ := io.ReadAll(spool)
			if !bytes.Equal(got, data) {
				t.Fatalf("got %q", got)
			}
		})
	}
	for name, value := range map[string][]byte{"bad-base64": []byte("not base64"), "wrong-width": []byte("AA==")} {
		t.Run(name, func(t *testing.T) {
			var body strings.Builder
			fmt.Fprintf(&body, "%x\r\n%s\r\n0\r\n%s: %s\r\n\r\n", len(data), data, "x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(value))
			r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader(body.String()))
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			r.Header.Set("Content-Encoding", "aws-chunked")
			r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
			r.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
			if _, err := verifyAndSpoolAWSBody(r, nil); err == nil {
				t.Fatal("malformed checksum accepted")
			}
		})
	}
}

func TestVerifiedAWSBody_CleanupOnEveryExit(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "s3gw-aws-body-*"))
	beforeSet := make(map[string]bool, len(before))
	for _, path := range before {
		beforeSet[path] = true
	}
	r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader("broken\n"))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", "1")
	c := &V4SigningContext{mode: streamingSignedPayload, signingKey: []byte("cleanup-key"), seedSignature: sha256.Sum256([]byte("seed"))}
	if _, err := verifyAndSpoolAWSBody(r, c); err == nil {
		t.Fatal("broken body accepted")
	}
	c.Close()
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "s3gw-aws-body-*"))
	for _, path := range after {
		if !beforeSet[path] {
			t.Fatalf("spool leak: unexpected path %s", path)
		}
	}
}

func TestSigV4Streaming_AWSDocumentedPayloadVector(t *testing.T) {
	// AWS documented example: sigv4-streaming.html, example PUT Object.
	const key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	const timestamp = "20130524T000000Z"
	const scope = "20130524/us-east-1/s3/aws4_request"
	seed, _ := hex.DecodeString("4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	var seedArray [32]byte
	copy(seedArray[:], seed)
	derived := getSignatureKey(key, "20130524", "us-east-1", "s3")
	c := &V4SigningContext{timestamp: timestamp, credentialScope: scope,
		signingKey: derived, seedSignature: seedArray, mode: streamingSignedPayload}
	defer c.Close()
	// The published vector uses 65536 'a', 1024 'a', then an empty chunk.
	parts := [][]byte{bytes.Repeat([]byte{'a'}, 65536), bytes.Repeat([]byte{'a'}, 1024), nil}
	published := []string{"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648", "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497", "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"}
	var fixture strings.Builder
	previous := seedArray
	for i, part := range parts {
		want := independentChunkHMAC(derived, timestamp, scope, previous, part)
		if hex.EncodeToString(want[:]) != published[i] {
			t.Fatalf("published HMAC %d was not independently reconstructed", i)
		}
		fmtChunk(&fixture, part, want)
		previous = want
	}
	fixtureBytes := []byte(fixture.String())
	var out bytes.Buffer
	if _, _, err := verifyAWSChunked(bufio.NewReader(bytes.NewReader(fixtureBytes)), &out, c, 66560, false); err != nil {
		t.Fatalf("AWS documented payload vector rejected: %v", err)
	}
	if len(out.Bytes()) != 66560 || !bytes.Equal(out.Bytes(), bytes.Repeat([]byte{'a'}, 66560)) {
		t.Fatalf("decoded payload length %d", out.Len())
	}
	bad := append([]byte(nil), fixtureBytes...)
	bad[len(bad)-70] ^= 1
	if _, _, err := verifyAWSChunked(bufio.NewReader(bytes.NewReader(bad)), &out, c, 3, false); err == nil {
		t.Fatal("mutated AWS vector accepted")
	}
}

func TestSigV4Streaming_AWSDocumentedTrailerVector(t *testing.T) {
	// AWS documented example: sigv4-streaming-trailers.html. The published
	// body is 65536 'a' bytes followed by 1024 'a' bytes.
	const key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	const timestamp = "20130524T000000Z"
	const scope = "20130524/us-east-1/s3/aws4_request"
	seedBytes, _ := hex.DecodeString("106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e")
	var seed [32]byte
	copy(seed[:], seedBytes)
	derived := getSignatureKey(key, "20130524", "us-east-1", "s3")
	c := &V4SigningContext{timestamp: timestamp, credentialScope: scope,
		signingKey: derived, seedSignature: seed, mode: streamingSignedPayloadTrailer}
	defer c.Close()
	first := bytes.Repeat([]byte{'a'}, 65536)
	second := bytes.Repeat([]byte{'a'}, 1024)
	chunk1 := independentChunkHMAC(derived, timestamp, scope, seed, first)
	chunk2 := independentChunkHMAC(derived, timestamp, scope, chunk1, second)
	zero := independentChunkHMAC(derived, timestamp, scope, chunk2, nil)
	if got := hex.EncodeToString(chunk1[:]); got != "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2" {
		t.Fatalf("chunk 1 HMAC %s", got)
	}
	if got := hex.EncodeToString(chunk2[:]); got != "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7" {
		t.Fatalf("chunk 2 HMAC %s", got)
	}
	if got := hex.EncodeToString(zero[:]); got != "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992" {
		t.Fatalf("zero HMAC %s", got)
	}
	trailerValue := "sOO8/Q=="
	trailerHash := sha256.Sum256([]byte("x-amz-checksum-crc32c:" + trailerValue + "\n"))
	trailerSig := independentHMAC(derived, []byte("AWS4-HMAC-SHA256-TRAILER\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(zero[:])+"\n"+hex.EncodeToString(trailerHash[:])))
	if got := hex.EncodeToString(trailerSig[:]); got != "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435" {
		t.Fatalf("trailer HMAC %s", got)
	}
	var body strings.Builder
	fmtChunk(&body, first, chunk1)
	fmtChunk(&body, second, chunk2)
	fmtChunk(&body, nil, zero)
	fmt.Fprintf(&body, "x-amz-checksum-crc32c: %s\r\nx-amz-trailer-signature: %s\r\n\r\n", trailerValue, hex.EncodeToString(trailerSig[:]))
	r := httptest.NewRequest(http.MethodPut, "http://example.test", strings.NewReader(body.String()))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32c")
	spool, err := verifyAndSpoolAWSBody(r, c)
	if err != nil {
		t.Fatalf("AWS documented trailer vector rejected: %v", err)
	}
	defer spool.Close()
	decoded, _ := io.ReadAll(spool)
	if len(decoded) != 66560 {
		t.Fatalf("decoded trailer payload length %d", len(decoded))
	}
	bad := []byte(body.String())
	bad[len(bad)-70] ^= 1
	r.Body = io.NopCloser(bytes.NewReader(bad))
	if _, err := verifyAndSpoolAWSBody(r, c); err == nil {
		t.Fatal("mutated trailer vector accepted")
	}
}

func independentHMAC(key, value []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(value)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func independentChunkHMAC(key []byte, timestamp, scope string, previous [32]byte, data []byte) [32]byte {
	d := sha256.Sum256(data)
	empty := sha256.Sum256(nil)
	input := "AWS4-HMAC-SHA256-PAYLOAD\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(previous[:]) + "\n" + hex.EncodeToString(empty[:]) + "\n" + hex.EncodeToString(d[:])
	return independentHMAC(key, []byte(input))
}
func fmtChunk(b *strings.Builder, data []byte, sig [32]byte) {
	fmt.Fprintf(b, "%x;chunk-signature=%s\r\n", len(data), hex.EncodeToString(sig[:]))
	if len(data) != 0 {
		b.Write(data)
		b.WriteString("\r\n")
	}
}

func TestAWSChunkedVerifier_StrictUnsigned(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single chunk",
			input:    "5\r\nhello\r\n0\r\n",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "multiple chunks",
			input:    "5\r\nhello\r\n6\r\n world\r\n0\r\n",
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "no extensions",
			input:    "d\r\nHello, world!\r\n0\r\n",
			expected: "Hello, world!",
			wantErr:  false,
		},
		{
			name:     "chunks with different sizes",
			input:    "2\r\nHi\r\n6\r\n there\r\n0\r\n",
			expected: "Hi there",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			b := bufio.NewReader(strings.NewReader(tt.input))
			_, _, err := verifyAWSChunked(b, &output, nil, -1, false)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, output.String())
			}
		})
	}
}

func TestAWSChunkedVerifier_LargeInput(t *testing.T) {
	// Construct a larger input with multiple chunks
	var buf bytes.Buffer
	expected := ""

	// Chunk 1
	buf.WriteString("a\r\n0123456789\r\n")
	expected += "0123456789"

	// Chunk 2
	buf.WriteString("5\r\nabcde\r\n")
	expected += "abcde"

	// Chunk 3 (longer)
	data := strings.Repeat("x", 100)
	buf.WriteString(strings.ToLower(string(strconv.FormatInt(int64(len(data)), 16))))
	buf.WriteString("\r\n")
	buf.WriteString(data)
	buf.WriteString("\r\n")
	expected += data

	// End
	buf.WriteString("0\r\n")

	var output bytes.Buffer
	_, _, err := verifyAWSChunked(bufio.NewReader(&buf), &output, nil, -1, false)

	assert.NoError(t, err)
	assert.Equal(t, expected, output.String())
}

func TestAWSChunkedVerifier_InvalidFormat(t *testing.T) {
	input := "invalid-hex\r\nhello\r\n0\r\n"
	var output bytes.Buffer
	_, _, err := verifyAWSChunked(bufio.NewReader(strings.NewReader(input)), &output, nil, -1, false)
	assert.Error(t, err)
}
