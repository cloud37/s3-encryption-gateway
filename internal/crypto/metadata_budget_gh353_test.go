package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestGH353FinalMetadataBudgetBoundaries(t *testing.T) {
	for _, provider := range []string{"default", "aws"} {
		t.Run(provider, func(t *testing.T) {
			profile := *GetProviderProfile(provider)
			profile.TotalHeaderLimit = 0
			for _, n := range []int{2048, 2049} {
				meta := map[string]string{MetaEncrypted: "true", MetaContentType: "text/plain"}
				base, err := NewMetadataCompactor(&profile).CompactMetadata(meta)
				if err != nil {
					t.Fatal(err)
				}
				used := EstimateMetadataSize(base)
				meta["X-Amz-Meta-User"] = strings.Repeat("x", n-used-len("X-Amz-Meta-User")-4)
				compacted, err := NewMetadataCompactor(&profile).CompactMetadata(meta)
				if err != nil {
					t.Fatal(err)
				}
				if got := profile.ValidateMetadataSize(compacted); (got != nil) != (n > 2048) {
					t.Fatalf("user size %d: %v", n, got)
				}
			}
			profile.UserMetadataLimit, profile.TotalHeaderLimit = 0, 8192
			for _, n := range []int{8192, 8193} {
				meta := map[string]string{MetaEncrypted: "true", MetaContentType: "text/plain"}
				base, err := NewMetadataCompactor(&profile).CompactMetadata(meta)
				if err != nil {
					t.Fatal(err)
				}
				meta["X-Amz-Meta-User"] = strings.Repeat("x", n-EstimateMetadataSize(base)-len("X-Amz-Meta-User")-4)
				compacted, err := NewMetadataCompactor(&profile).CompactMetadata(meta)
				if err != nil {
					t.Fatal(err)
				}
				if got := profile.ValidateMetadataSize(compacted); (got != nil) != (n > 8192) {
					t.Fatalf("total size %d: %v", n, got)
				}
			}
		})
	}
}

func TestGH353FinalMetadataFallbackStreaming(t *testing.T) {
	for _, keyed := range []bool{false, true} {
		opts := []Option{WithProvider("minio"), WithChunking(true), WithPBKDF2Iterations(MinPBKDF2Iterations)}
		if keyed {
			opts = append(opts, WithMetadataKey(bytes.Repeat([]byte{3}, 32)))
		}
		enc, err := NewEngineWithOpts([]byte("metadata-budget-test-password"), opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = enc.(io.Closer).Close() })
		input := &profileObservedReader{reader: bytes.NewReader([]byte("plain"))}
		out, headers, err := enc.Encrypt(t.Context(), ObjectContext{Bucket: "bucket", Key: "key"}, input, map[string]string{"x-amz-meta-overflow": strings.Repeat("v", 7900), "x-amz-meta-owner": "owner", "Content-Type": "text/plain"})
		if err != nil {
			t.Fatal(err)
		}
		if input.bytesRead != 0 {
			t.Fatal("source consumed during fallback selection")
		}
		if err := GetProviderProfile("minio").ValidateMetadataSize(persistedMetadataEnvelope(headers)); err != nil {
			t.Fatal(err)
		}
		if headers["x-amz-meta-overflow"] != "" || headers["x-amz-meta-owner"] != "owner" {
			t.Fatal("incorrect fallback projection")
		}
		expanded, err := ExpandMetadataForAPI(headers)
		if err != nil {
			t.Fatal(err)
		}
		if expanded[MetaFallbackVersion] != "2" || expanded[MetaEncrypted] != "true" {
			t.Fatal("missing fallback controls")
		}
		if keyed && expanded[MetaEncryptedMetadata] == "" {
			t.Fatal("missing mandatory sealed blob")
		}
		data, err := io.ReadAll(out)
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := ReadFallbackV2Prefix(t.Context(), bytes.NewReader(data))
		if err != nil || prefix["x-amz-meta-overflow"] != strings.Repeat("v", 7900) {
			t.Fatalf("prefix: %v", err)
		}
		plain, meta, err := enc.Decrypt(t.Context(), ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(data), headers)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(plain)
		if err != nil || string(body) != "plain" || meta["x-amz-meta-overflow"] != strings.Repeat("v", 7900) {
			t.Fatalf("roundtrip: %v", err)
		}
	}
}

func TestGH353FallbackMandatoryHeaderTooLarge(t *testing.T) {
	enc, err := NewEngineWithOpts([]byte("metadata-budget-test-password"), WithProvider("aws"), WithChunking(true), WithPBKDF2Iterations(MinPBKDF2Iterations))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = enc.(io.Closer).Close() })
	source := &profileObservedReader{reader: bytes.NewReader([]byte("plain"))}
	_, _, err = enc.Encrypt(t.Context(), ObjectContext{Bucket: "b", Key: "k"}, source, map[string]string{"Content-Type": strings.Repeat("a", 3000)})
	if !errors.Is(err, ErrMetadataTooLarge) || source.bytesRead != 0 {
		t.Fatalf("err=%v read=%d", err, source.bytesRead)
	}
}

func TestGH353FinalMetadataProviderAliases(t *testing.T) {
	for _, tc := range []struct{ name, want string }{{"", "default"}, {"unknown", "default"}, {"AMAZON", "aws"}, {"min.io", "minio"}, {"b2", "backblaze"}} {
		enc, err := NewEngineWithOpts([]byte("provider-test-password"), WithProvider(tc.name), WithPBKDF2Iterations(MinPBKDF2Iterations))
		if err != nil {
			t.Fatal(err)
		}
		if got := enc.(*engine).providerProfile.Name; got != tc.want {
			t.Fatalf("provider %q got %q", tc.name, got)
		}
		_ = enc.(io.Closer).Close()
	}
}

func TestGH353FinalMetadataBufferedKeyedFallback(t *testing.T) {
	enc, err := NewEngineWithOpts([]byte("metadata-budget-test-password"), WithProvider("aws"), WithMetadataKey(bytes.Repeat([]byte{7}, 32)), WithPBKDF2Iterations(MinPBKDF2Iterations))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = enc.(io.Closer).Close() })
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	reader, headers, err := enc.Encrypt(t.Context(), obj, bytes.NewReader([]byte("buffered")), map[string]string{"x-amz-meta-overflow": strings.Repeat("x", 7900), "Content-Type": "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if err := GetProviderProfile("aws").ValidateMetadataSize(persistedMetadataEnvelope(headers)); err != nil {
		t.Fatal(err)
	}
	if headers[MetaEncryptedMetadataCompact] == "" {
		t.Fatal("sealed blob missing")
	}
	view, err := enc.(*engine).APIExpandedMetadata(headers)
	if err != nil || view[MetaFallbackVersion] != "3" || view[MetaObjectFormatVersion] != "buffered-fallback-v2" {
		t.Fatalf("view=%v err=%v", view, err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, meta, err := enc.Decrypt(t.Context(), obj, bytes.NewReader(data), headers)
	if err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(plain)
	if err != nil || string(result) != "buffered" || meta["x-amz-meta-overflow"] != strings.Repeat("x", 7900) || meta["Content-Type"] != "text/plain" {
		t.Fatalf("buffered fallback roundtrip: %v", err)
	}
}

func TestGH353FinalMetadataKeyedProtectedNonFallback(t *testing.T) {
	enc, err := NewEngineWithOpts([]byte("metadata-budget-test-password"), WithProvider("aws"), WithChunking(true), WithMetadataKey(bytes.Repeat([]byte{5}, 32)), WithPBKDF2Iterations(MinPBKDF2Iterations))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = enc.(io.Closer).Close() })
	fields := map[string]string{"Content-Type": "text/plain", "Content-Encoding": "gzip", "Content-Disposition": "inline", "Content-Language": "en", "Cache-Control": "no-cache", "Expires": "Wed, 21 Oct 2037 07:28:00 GMT", "x-amz-meta-owner": "owner"}
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	reader, headers, err := enc.Encrypt(t.Context(), obj, bytes.NewReader([]byte("plain")), fields)
	if err != nil {
		t.Fatal(err)
	}
	view, err := enc.(*engine).APIExpandedMetadata(headers)
	if err != nil {
		t.Fatal(err)
	}
	if view[MetaFallbackMode] != "" || headers[MetaEncryptedMetadataCompact] == "" {
		t.Fatal("expected a retained sealed blob without fallback")
	}
	if err := GetProviderProfile("aws").ValidateMetadataSize(persistedMetadataEnvelope(headers)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, restored, err := enc.Decrypt(t.Context(), obj, bytes.NewReader(data), headers)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(plain)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		if restored[k] != v {
			t.Fatalf("field %s did not round trip", k)
		}
	}
}
