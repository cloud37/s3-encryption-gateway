package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func TestResolvePlaintextSize_LegacyFallbackRequiresKnownAlgorithm(t *testing.T) {
	h := &Handler{}
	for _, tc := range []struct {
		name, algorithm string
		wantSize        int64
		wantExact       bool
	}{
		{name: "AES GCM", algorithm: crypto.AlgorithmAES256GCM, wantSize: 84, wantExact: true},
		{name: "unknown algorithm", algorithm: "future-aead", wantSize: -1},
		{name: "missing algorithm", wantSize: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]string{crypto.MetaEncrypted: "true", "Content-Length": "100"}
			if tc.algorithm != "" {
				meta[crypto.MetaAlgorithm] = tc.algorithm
			}
			view, err := h.loadObjectView("bucket", "key", nil, meta)
			if err != nil {
				t.Fatal(err)
			}
			got, err := h.resolvePlaintextSize(context.Background(), nil, view)
			if err != nil {
				t.Fatal(err)
			}
			if got.Size != tc.wantSize || got.Exact != tc.wantExact {
				t.Fatalf("resolved size=%+v, want size=%d exact=%t", got, tc.wantSize, tc.wantExact)
			}
		})
	}
}

func TestResolvePlaintextSize_FallbackDoesNotGuessFromCiphertext(t *testing.T) {
	h := &Handler{}
	view, err := h.loadObjectView("bucket", "key", nil, map[string]string{
		crypto.MetaEncrypted: "true", crypto.MetaFallbackMode: "v1", crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		"Content-Length": "100",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.resolvePlaintextSize(context.Background(), nil, view)
	if err != nil {
		t.Fatal(err)
	}
	if got.Exact || got.Size != -1 {
		t.Fatalf("fallback size guessed from ciphertext: %+v", got)
	}
}

func TestResolvePlaintextSize_InvalidOriginalSizeAndPlaintextBackend(t *testing.T) {
	h := &Handler{}
	if _, err := h.resolvePlaintextSize(context.Background(), nil, nil); err == nil {
		t.Fatal("nil object view accepted")
	}
	for _, tc := range []struct {
		name     string
		meta     map[string]string
		wantErr  bool
		wantSize int64
	}{
		{"bad encrypted original size", map[string]string{crypto.MetaEncrypted: "true", crypto.MetaOriginalSize: "bad"}, true, -1},
		{"negative encrypted original size", map[string]string{crypto.MetaEncrypted: "true", crypto.MetaOriginalSize: "-1"}, true, -1},
		{"plaintext backend size", map[string]string{"Content-Length": "32"}, false, 32},
		{"negative plaintext backend size", map[string]string{"Content-Length": "-1"}, false, -1},
		{"malformed plaintext backend size", map[string]string{"Content-Length": "invalid"}, false, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view, err := h.loadObjectView("bucket", "key", nil, tc.meta)
			if err != nil {
				t.Fatal(err)
			}
			got, err := h.resolvePlaintextSize(context.Background(), nil, view)
			if tc.wantErr != (err != nil) || got.Size != tc.wantSize {
				t.Fatalf("size=%+v err=%v", got, err)
			}
		})
	}
}

func TestResolvePlaintextSize_ChunkedFormulaErrorDoesNotUseFallback(t *testing.T) {
	h := &Handler{}
	view := &objectView{Bucket: "bucket", Key: "key", Raw: map[string]string{"Content-Length": "invalid"}, Expanded: map[string]string{
		crypto.MetaOriginalSize: "42", "Content-Length": "100",
	}, Class: crypto.ObjectClass{Format: crypto.FormatChunkedV1, Encrypted: true}}
	if _, err := h.resolvePlaintextSize(context.Background(), nil, view); err == nil {
		t.Fatal("invalid chunked formula was hidden by original-size fallback")
	}
}

func TestResolvePlaintextSize_FormatPolicyBranches(t *testing.T) {
	h := &Handler{}
	t.Run("plaintext missing length", func(t *testing.T) {
		got, err := metadataSize(nil, "backend")
		if err != nil || got.Exact || got.Size != -1 {
			t.Fatalf("size=%+v err=%v", got, err)
		}
	})
	t.Run("fallback malformed size", func(t *testing.T) {
		view := &objectView{Expanded: map[string]string{crypto.MetaOriginalSize: "bad"}, Class: crypto.ObjectClass{Format: crypto.FormatBufferedFallback, Encrypted: true}}
		if _, err := h.resolvePlaintextSize(context.Background(), nil, view); err == nil {
			t.Fatal("malformed fallback size accepted")
		}
	})
	t.Run("legacy malformed original size", func(t *testing.T) {
		view := &objectView{Expanded: map[string]string{crypto.MetaOriginalSize: "-4"}, Class: crypto.ObjectClass{Format: crypto.FormatBufferedLegacy, Encrypted: true}}
		if _, err := h.resolvePlaintextSize(context.Background(), nil, view); err == nil {
			t.Fatal("negative original size accepted")
		}
	})
	t.Run("legacy unsupported algorithm", func(t *testing.T) {
		view := &objectView{Expanded: map[string]string{crypto.MetaAlgorithm: "future", "Content-Length": "100"}, Class: crypto.ObjectClass{Format: crypto.FormatBufferedLegacy, Encrypted: true}}
		got, err := h.resolvePlaintextSize(context.Background(), nil, view)
		if err != nil || got.Exact || got.Size != -1 {
			t.Fatalf("size=%+v err=%v", got, err)
		}
	})
	t.Run("legacy aead size at exact overhead", func(t *testing.T) {
		overhead, err := crypto.AEADOverheadForAlgorithm(crypto.AlgorithmAES256GCM)
		if err != nil {
			t.Fatal(err)
		}
		view := &objectView{Expanded: map[string]string{crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM, "Content-Length": fmt.Sprint(overhead)}, Class: crypto.ObjectClass{Format: crypto.FormatBufferedLegacy, Encrypted: true}}
		got, err := h.resolvePlaintextSize(context.Background(), nil, view)
		if err != nil || !got.Exact || got.Size != 0 {
			t.Fatalf("size=%+v err=%v", got, err)
		}
	})
	t.Run("legacy malformed backend length", func(t *testing.T) {
		view := &objectView{Expanded: map[string]string{crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM, "Content-Length": "bad"}, Class: crypto.ObjectClass{Format: crypto.FormatBufferedLegacy, Encrypted: true}}
		got, err := h.resolvePlaintextSize(context.Background(), nil, view)
		if err != nil || got.Exact || got.Size != -1 {
			t.Fatalf("size=%+v err=%v", got, err)
		}
	})
	t.Run("chunked v1 formula", func(t *testing.T) {
		manifest, _ := json.Marshal(map[string]any{"v": 1, "cs": crypto.DefaultChunkSize, "cc": 1, "iv": "AAAAAAAAAAAAAAAA"})
		view := &objectView{Raw: map[string]string{"Content-Length": "116"}, Expanded: map[string]string{crypto.MetaManifest: base64.StdEncoding.EncodeToString(manifest), "Content-Length": "116"}, Class: crypto.ObjectClass{Format: crypto.FormatChunkedV1, Encrypted: true}}
		got, err := h.resolvePlaintextSize(context.Background(), nil, view)
		if err != nil || !got.Exact || got.Size != 100 {
			t.Fatalf("size=%+v err=%v", got, err)
		}
	})
	t.Run("chunked invalid length", func(t *testing.T) {
		view := &objectView{Raw: map[string]string{"Content-Length": "invalid"}, Expanded: map[string]string{crypto.MetaManifest: "e30=", "Content-Length": "invalid"}, Class: crypto.ObjectClass{Format: crypto.FormatChunkedV1, Encrypted: true}}
		if _, err := h.resolvePlaintextSize(context.Background(), nil, view); err == nil {
			t.Fatal("invalid chunked ciphertext length accepted")
		}
	})
}

func TestResolvePlaintextSize_CompactOriginalSizeAlias(t *testing.T) {
	h := &Handler{}
	view, err := h.loadObjectView("bucket", "key", nil, map[string]string{
		crypto.MetaEncrypted: "true", "x-amz-meta-os": "47",
	})
	if err != nil {
		t.Fatal(err)
	}
	size, err := h.resolvePlaintextSize(context.Background(), nil, view)
	if err != nil || !size.Exact || size.Size != 47 {
		t.Fatalf("compact original-size resolution=%+v err=%v, want exact 47", size, err)
	}
}

func TestLookupListObjectPlaintextSize_UsesResolverForMPUV1AndEmptyObjects(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "list-resolver-*")
	ctx := context.Background()
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, TotalPlainSize: 23,
		Parts: []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: 23, EncLen: 39, ChunkCount: 1}}}
	manifestBody, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	key := "list-resolver-object"
	manifestKey := key + crypto.MPUManifestSuffix
	engine, err := h.getEncryptionEngine("list-resolver-bucket")
	if err != nil {
		t.Fatal(err)
	}
	sealedManifest, sealedMeta, err := engine.Encrypt(ctx, crypto.ObjectContext{Bucket: "list-resolver-bucket", Key: manifestKey}, bytes.NewReader(manifestBody), nil)
	if err != nil {
		t.Fatal(err)
	}
	manifestCiphertext, err := io.ReadAll(sealedManifest)
	if err != nil {
		t.Fatal(err)
	}
	client.objects["list-resolver-bucket/"+key] = []byte("ciphertext bytes")
	client.metadata["list-resolver-bucket/"+key] = map[string]string{crypto.MetaMPUEncrypted: "true"}
	client.objects["list-resolver-bucket/"+manifestKey] = manifestCiphertext
	client.metadata["list-resolver-bucket/"+manifestKey] = sealedMeta
	got, ok, err := h.lookupListObjectPlaintextSize(ctx, "list-resolver-bucket", key, 16, client)
	if err != nil || !ok || got != 23 {
		t.Fatalf("MPU list size=(%d,%t,%v), want (23,true,nil)", got, ok, err)
	}
	manifestSize, err := h.loadMPUManifestSize(ctx, client, "list-resolver-bucket", key, client.metadata["list-resolver-bucket/"+key])
	if err != nil || manifestSize != 23 {
		t.Fatalf("manifest wrapper size=(%d,%v), want (23,nil)", manifestSize, err)
	}
	if _, err := h.loadMPUManifest(ctx, client, "list-resolver-bucket", "not-mpu", crypto.ObjectClass{Format: crypto.FormatPlaintext}); err == nil {
		t.Fatal("manifest loader accepted a non-MPU class")
	}
	_, err = h.loadMPUManifest(ctx, client, "list-resolver-bucket", key, crypto.ObjectClass{Format: crypto.FormatMPUV1, Encrypted: true, ManifestKey: manifestKey})
	if err != nil {
		t.Fatalf("valid MPU manifest rejected: %v", err)
	}
	missingManifestClass := crypto.ObjectClass{Format: crypto.FormatMPUV1, Encrypted: true, ManifestKey: "absent" + crypto.MPUManifestSuffix}
	if _, err := h.loadMPUManifest(ctx, client, "list-resolver-bucket", "absent", missingManifestClass); err == nil || !strings.Contains(err.Error(), "fetch manifest") {
		t.Fatalf("missing MPU manifest error=%v", err)
	}
	plainKey := "list-resolver-empty"
	client.objects["list-resolver-bucket/"+plainKey] = []byte{}
	client.metadata["list-resolver-bucket/"+plainKey] = map[string]string{"Content-Length": "0"}
	got, ok, err = h.lookupListObjectPlaintextSize(ctx, "list-resolver-bucket", plainKey, 0, client)
	if err != nil || !ok || got != 0 {
		t.Fatalf("empty plaintext size=(%d,%t,%v), want (0,true,nil)", got, ok, err)
	}
}

func TestRecordPlaintextSize_NoCacheAndInexactAreNoops(t *testing.T) {
	ctx := context.Background()
	(&Handler{}).recordPlaintextSize(ctx, "bucket", "key", plaintextSize{Size: 1, Exact: true})
	h, _, sc := newListObjectsTestHandlerWithSizeCache(t, config.ListSizeTranslateConfig{})
	h.recordPlaintextSize(ctx, "bucket", "inexact", plaintextSize{Size: 1, Exact: false})
	h.recordPlaintextSize(ctx, "bucket", "negative", plaintextSize{Size: -1, Exact: true})
	values, err := sc.GetBatch(ctx, "bucket", []string{"inexact", "negative"})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 {
		t.Fatalf("inexact sizes were cached: %v", values)
	}

	cacheErr := &failingSizeCache{}
	h.sizeCache = cacheErr
	h.logger = logrus.New()
	h.recordPlaintextSize(ctx, "bucket", "failed-write", plaintextSize{Size: 4, Exact: true})
	if cacheErr.writes != 1 {
		t.Fatalf("cache writes=%d want 1", cacheErr.writes)
	}
}

type failingSizeCache struct{ writes int }

func (c *failingSizeCache) Set(context.Context, string, string, int64) error {
	c.writes++
	return errors.New("cache unavailable")
}

func (*failingSizeCache) GetBatch(context.Context, string, []string) (map[string]int64, error) {
	return nil, errors.New("cache unavailable")
}

func (*failingSizeCache) SetBatch(context.Context, string, map[string]int64) error {
	return errors.New("cache unavailable")
}
func (*failingSizeCache) Delete(context.Context, string, string) error        { return nil }
func (*failingSizeCache) DeleteBatch(context.Context, string, []string) error { return nil }
func (*failingSizeCache) Close() error                                        { return nil }
