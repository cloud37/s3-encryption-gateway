package crypto

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestGH353EncryptionWriteProfile_StreamingAndBuffered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chunked bool
		want    bool
	}{
		{"buffered", false, false}, {"chunked", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encEngine, err := NewEngineWithChunkingAndProvider([]byte("write-profile-test-password"), "", nil, tc.chunked, MinChunkSize, "default", MinPBKDF2Iterations)
			if err != nil {
				t.Fatal(err)
			}
			concrete := encEngine.(*engine)
			if tc.chunked {
				profile := &ProviderProfile{Name: "GH353-test", UserMetadataLimit: 2048, TotalHeaderLimit: 8192, SupportsLongKeys: true, CompactionStrategy: "base64url"}
				concrete.providerProfile = profile
				concrete.compactor = NewMetadataCompactor(profile)
			}
			profiler, ok := encEngine.(EncryptionWriteProfiler)
			if !ok || profiler.WriteProfile().StreamsPlaintext != tc.want {
				t.Fatalf("profile=%+v ok=%v", profiler.WriteProfile(), ok)
			}
			data := bytes.Repeat([]byte("x"), 512*1024)
			metadataInput := map[string]string{}
			if tc.chunked {
				metadataInput["x-amz-meta-long-key"] = strings.Repeat("v", 7900)
			}
			plaintext := &profileObservedReader{reader: bytes.NewReader(data)}
			encrypted, metadata, err := encEngine.Encrypt(context.Background(), ObjectContext{Bucket: "bucket", Key: "key"}, plaintext, metadataInput)
			if err != nil {
				t.Fatalf("Encrypt metadata-overflow fixture: %v", err)
			}
			metadata, err = ExpandMetadataForAPI(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if tc.chunked && metadata[MetaFallbackMode] != "true" {
				t.Fatalf("chunked metadata overflow did not select streaming fallback: %v", metadata)
			}
			bounded := &profileBoundedReader{reader: encrypted, max: 257}
			if _, err := io.Copy(io.Discard, bounded); err != nil {
				t.Fatalf("drain streaming output: %v", err)
			}
			if bounded.maxObserved > bounded.max {
				t.Fatalf("reader returned %d bytes at once, bound %d", bounded.maxObserved, bounded.max)
			}
			if tc.chunked && (plaintext.maxRequested >= len(data) || plaintext.bytesRead != int64(len(data))) {
				t.Fatalf("chunked fallback input requests max=%d consumed=%d total=%d", plaintext.maxRequested, plaintext.bytesRead, len(data))
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 100; j++ {
						if got := profiler.WriteProfile(); got.StreamsPlaintext != tc.want {
							t.Errorf("profile changed concurrently: %+v", got)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
	if got := (PassthroughEngine{}).WriteProfile(); !got.StreamsPlaintext {
		t.Fatalf("passthrough profile=%+v", got)
	}
}

type profileObservedReader struct {
	reader       io.Reader
	maxRequested int
	bytesRead    int64
}

func (r *profileObservedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRequested {
		r.maxRequested = len(p)
	}
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

type profileBoundedReader struct {
	reader      io.Reader
	max         int
	maxObserved int
}

func (r *profileBoundedReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	n, err := r.reader.Read(p)
	if n > r.maxObserved {
		r.maxObserved = n
	}
	return n, err
}
