package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Match S3's ranged response Content-Length rather than the full HEAD length.
type gh409Client struct {
	*mockS3Client
	ranges    []string
	beforeGet func(int)
}

func (c *gh409Client) GetObject(ctx context.Context, bucket, key string, versionID, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	value := "full"
	if rangeHeader != nil {
		value = *rangeHeader
	}
	c.ranges = append(c.ranges, value)
	if c.beforeGet != nil {
		c.beforeGet(len(c.ranges))
	}
	reader, meta, err := c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
	if err != nil || rangeHeader == nil {
		return reader, meta, err
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		return nil, nil, err
	}
	meta = maps.Clone(meta)
	meta["Content-Length"] = strconv.Itoa(len(data))
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func TestGH409_ChangedObjectAfterTerminalPreflightFailsClosed(t *testing.T) {
	client, router, _ := gh409Fixture(t, false)
	replacement, _, plain := gh409Fixture(t, false)
	client.ranges = nil
	client.beforeGet = func(call int) {
		if call == 2 {
			client.objects["bucket/key"] = replacement.objects["bucket/key"]
			client.metadata["bucket/key"] = replacement.metadata["bucket/key"]
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set("Range", "bytes=16500-16531")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || len(client.ranges) != 2 || bytes.Contains(w.Body.Bytes(), plain[16500:16532]) {
		t.Fatalf("changed object: status=%d ranges=%v body=%q", w.Code, client.ranges, w.Body.String())
	}
}

func gh409Fixture(t *testing.T, protected bool) (*gh409Client, *mux.Router, []byte) {
	t.Helper()
	client := &gh409Client{mockS3Client: newMockS3Client()}
	engine, err := newAPIUnitChunkedEngine([]byte("gh409-range-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		crypto.SetMetadataKey(engine, bytes.Repeat([]byte{7}, 32))
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	h := NewHandler(client, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	plain := makeByteRamp(crypto.MinChunkSize*3+137, 31)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(plain)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", w.Code, w.Body.String())
	}
	meta := client.metadata["bucket/key"]
	expanded, err := crypto.ExpandMetadataForAPI(meta)
	if err != nil || expanded[crypto.MetaObjectFormatVersion] != "chunked-v2" || expanded[crypto.MetaChunkCount] != "" {
		t.Fatalf("not an authentic single-PUT chunked-v2 object without chunk count: meta=%v err=%v", expanded, err)
	}
	return client, router, plain
}

func TestGH409_SinglePutRangesUseBoundedBackendReads(t *testing.T) {
	const chunk = crypto.MinChunkSize
	tests := []struct {
		name, header                      string
		start, end, firstChunk, lastChunk int
	}{
		{"start", "bytes=0-31", 0, 31, 0, 0},
		{"middle", "bytes=16500-16531", 16500, 16531, 1, 1},
		{"boundary", "bytes=16380-16390", 16380, 16390, 0, 1},
		{"end", "bytes=49288-49288", 49288, 49288, 3, 3},
		{"suffix", "bytes=-10", 49279, 49288, 3, 3},
		{"open ended", "bytes=32800-", 32800, 49288, 2, 3},
	}
	for _, variant := range []string{"original", "missing-size", "stale-size", "compact", "protected"} {
		for _, tc := range tests {
			t.Run(variant+"/"+tc.name, func(t *testing.T) {
				client, router, plain := gh409Fixture(t, variant == "protected")
				meta := client.metadata["bucket/key"]
				switch variant {
				case "missing-size":
					delete(meta, crypto.MetaOriginalSize)
				case "stale-size":
					meta[crypto.MetaOriginalSize] = "1"
				case "compact":
					var err error
					client.metadata["bucket/key"], err = crypto.NewMetadataCompactor(crypto.ProviderAWS).CompactMetadata(meta)
					if err != nil {
						t.Fatal(err)
					}
					if !crypto.HasCompactAlias(client.metadata["bucket/key"]) {
						t.Fatal("fixture metadata was not compacted")
					}
				}
				cipherSize := len(client.objects["bucket/key"])
				terminal := fmt.Sprintf("bytes=%d-%d", cipherSize-crypto.ChunkedTerminalSize, cipherSize-1)
				first := tc.firstChunk * (chunk + 16)
				last := (tc.lastChunk+1)*(chunk+16) - 1
				if last >= cipherSize-crypto.ChunkedTerminalSize {
					last = cipherSize - crypto.ChunkedTerminalSize - 1
				}
				dataRange := fmt.Sprintf("bytes=%d-%d", first, last)
				client.ranges = nil
				req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
				req.Header.Set("Range", tc.header)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), plain[tc.start:tc.end+1]) {
					t.Fatalf("GET status=%d body length=%d, ranges=%v body=%q", w.Code, w.Body.Len(), client.ranges, w.Body.String())
				}
				if got, want := w.Header().Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(plain)); got != want {
					t.Fatalf("Content-Range=%q want=%q", got, want)
				}
				if got, want := w.Header().Get("Content-Length"), strconv.Itoa(tc.end-tc.start+1); got != want {
					t.Fatalf("Content-Length=%q want=%q", got, want)
				}
				if !reflect.DeepEqual(client.ranges, []string{terminal, dataRange}) {
					t.Fatalf("backend reads=%v want=%v", client.ranges, []string{terminal, dataRange})
				}
			})
		}
	}
}

func TestGH409_FullRangeAndIntegrity(t *testing.T) {
	for _, mode := range []string{"full", "explicit-full", "terminal-tamper", "first-chunk-tamper", "bad-manifest", "bad-length", "unsatisfiable"} {
		t.Run(mode, func(t *testing.T) {
			client, router, plain := gh409Fixture(t, false)
			ciphertext := client.objects["bucket/key"]
			header := "bytes=16500-16531"
			switch mode {
			case "full":
				header = "bytes=0-"
			case "explicit-full":
				header = fmt.Sprintf("bytes=0-%d", len(plain)-1)
			case "terminal-tamper":
				ciphertext[len(ciphertext)-1] ^= 1
			case "first-chunk-tamper":
				ciphertext[crypto.MinChunkSize+16+5] ^= 1
			case "bad-manifest":
				client.metadata["bucket/key"][crypto.MetaManifest] = "invalid"
			case "bad-length":
				client.metadata["bucket/key"]["Content-Length"] = "invalid"
			case "unsatisfiable":
				header = fmt.Sprintf("bytes=%d-", len(plain))
			}
			client.ranges = nil
			req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			req.Header.Set("Range", header)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			terminal := fmt.Sprintf("bytes=%d-%d", len(ciphertext)-crypto.ChunkedTerminalSize, len(ciphertext)-1)
			if mode == "full" || mode == "explicit-full" {
				if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), plain) || !reflect.DeepEqual(client.ranges, []string{terminal, "full"}) {
					t.Fatalf("full: status=%d ranges=%v", w.Code, client.ranges)
				}
				return
			}
			if mode == "unsatisfiable" {
				if w.Code != http.StatusRequestedRangeNotSatisfiable || !reflect.DeepEqual(client.ranges, []string{terminal, "full"}) {
					t.Fatalf("unsatisfiable: status=%d ranges=%v", w.Code, client.ranges)
				}
				return
			}
			want := []string{terminal}
			if mode == "bad-manifest" || mode == "bad-length" {
				want = nil
			}
			if mode == "first-chunk-tamper" {
				want = append(want, "bytes=16400-32799")
			}
			if w.Code != http.StatusInternalServerError || !reflect.DeepEqual(client.ranges, want) || bytes.Contains(w.Body.Bytes(), plain[16500:16532]) {
				t.Fatalf("integrity: status=%d ranges=%v body=%q", w.Code, client.ranges, w.Body.String())
			}
		})
	}
}

func TestGH409_LegacyChunkedV1WithoutSizeHintsUsesFullFetch(t *testing.T) {
	plain := makeByteRamp(crypto.MinChunkSize*2+137, 19)
	data, meta, err := makeLegacyChunkedFixture(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	delete(meta, crypto.MetaOriginalSize)
	delete(meta, crypto.MetaChunkCount)
	client := &gh409Client{mockS3Client: newMockS3Client()}
	client.objects["bucket/key"], client.metadata["bucket/key"] = data, meta
	engine, err := newAPIUnitChunkedEngine([]byte(goldenPassword), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	router := mux.NewRouter()
	NewHandler(client, engine, logger, getTestMetrics()).RegisterRoutes(router)
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set("Range", "bytes=16500-16531")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), plain[16500:16532]) || !reflect.DeepEqual(client.ranges, []string{"full"}) {
		t.Fatalf("legacy status=%d ranges=%v body=%q", w.Code, client.ranges, w.Body.String())
	}
}
