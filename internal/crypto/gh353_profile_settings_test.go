package crypto

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestGH353MetadataProfileResolution(t *testing.T) {
	for _, provider := range []string{"", "backblaze-b2", "wasabi", "minio"} {
		original := *GetProviderProfile(provider)
		for _, mode := range []string{"", "auto", "compact"} {
			got, err := ResolveMetadataProfile(provider, mode)
			if err != nil {
				t.Fatal(err)
			}
			want := original
			if mode == "compact" {
				want.CompactionStrategy = "base64url"
			}
			if *got != want || got == GetProviderProfile(provider) || got.UserMetadataLimit != 2048 || got.TotalHeaderLimit != 8192 {
				t.Fatalf("unexpected profile: %+v", got)
			}
			got.UserMetadataLimit = 1
			if *GetProviderProfile(provider) != original {
				t.Fatal("global profile mutated")
			}
		}
	}
	if _, err := ResolveMetadataProfile("unknown", "COMPACT"); err == nil {
		t.Fatal("invalid profile accepted")
	}
	if _, err := NewEngineWithOpts([]byte("provider-config-password"), WithMetadataProfile("unknown", "invalid")); err == nil {
		t.Fatal("invalid engine profile accepted")
	}
}

func TestGH353CompactProfileProtectedOverflow(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		enc, err := NewEngineWithOpts([]byte("metadata-budget-test-password"), WithMetadataProfile("backblaze-b2", "compact"), WithChunking(chunked), WithMetadataKey(bytes.Repeat([]byte{7}, 32)), WithPBKDF2Iterations(MinPBKDF2Iterations))
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{"Content-Type": "text/plain", "Content-Encoding": "identity", "Content-Disposition": "inline", "Content-Language": "en", "Cache-Control": "no-cache", "Expires": "Wed, 21 Oct 2037 07:28:00 GMT", "x-amz-meta-overflow": strings.Repeat("v", 7900)}
		obj := ObjectContext{Bucket: "bucket", Key: "key"}
		reader, headers, err := enc.Encrypt(t.Context(), obj, bytes.NewReader([]byte("payload")), fields)
		if err != nil {
			t.Fatal(err)
		}
		profile, _ := ResolveMetadataProfile("backblaze-b2", "compact")
		if err := profile.ValidateMetadataSize(persistedMetadataEnvelope(headers)); err != nil {
			t.Fatal(err)
		}
		wire, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		plain, restored, err := enc.Decrypt(t.Context(), obj, bytes.NewReader(wire), headers)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(plain)
		if err != nil || string(body) != "payload" {
			t.Fatal("payload mismatch")
		}
		for k, v := range fields {
			if restored[k] != v {
				t.Fatalf("protected metadata %s missing", k)
			}
		}
		_ = enc.(io.Closer).Close()
	}
}

func TestGH353MetadataProfileCrossDecrypt(t *testing.T) {
	for _, kind := range []bool{false, true} {
		for _, from := range []string{"auto", "compact"} {
			for _, to := range []string{"auto", "compact"} {
				ctx := t.Context()
				object := ObjectContext{Bucket: "bucket", Key: "key"}
				options := func(mode string) []Option {
					return []Option{WithMetadataProfile("backblaze-b2", mode), WithChunking(kind), WithPBKDF2Iterations(MinPBKDF2Iterations)}
				}
				writer, err := NewEngineWithOpts([]byte("test password"), options(from)...)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := NewEngineWithOpts([]byte("test password"), options(to)...)
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, meta, err := writer.Encrypt(ctx, object, bytes.NewReader([]byte("cross profile")), nil)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := io.ReadAll(ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				plain, _, err := reader.Decrypt(ctx, object, bytes.NewReader(wire), meta)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(plain)
				if err != nil || string(got) != "cross profile" {
					t.Fatal("cross-profile decryption failed")
				}
				_ = writer.(io.Closer).Close()
				_ = reader.(io.Closer).Close()
			}
		}
	}
}
