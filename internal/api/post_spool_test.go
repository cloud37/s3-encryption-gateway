package api

import (
	"bytes"
	"context"
	"crypto/md5" // S3 Content-MD5 test vector.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeSpoolUpload(t *testing.T, file []byte, minimum, maximum int64, overhead int) *postUpload {
	t.Helper()
	body, contentType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, `Content-Disposition: form-data; name="file"; filename="x"`, string(file))
	if overhead > 0 {
		body = strings.Replace(body, "name=\"key\"\r\n\r\nk", fmt.Sprintf("name=\"key\"\r\nX-Pad: %s\r\n\r\nk", strings.Repeat("x", overhead)), 1)
	}
	r := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	upload, err := parsePostUpload(r, 1<<20)
	if err != nil {
		t.Fatalf("parsePostUpload: %v", err)
	}
	upload.minimumFileSize, upload.maximumFileSize = minimum, maximum
	return upload
}

func TestGH353PostSpool_EntryGuardsAndLimitDefaults(t *testing.T) {
	manager := NewSpoolManager(64, t.TempDir())
	if _, err := spoolPostFile(nil, &postUpload{}, manager, 8); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := spoolPostFile(context.Background(), nil, manager, 8); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("nil upload error=%v", err)
	}
	if _, err := spoolPostFile(context.Background(), &postUpload{}, nil, 8); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("nil manager error=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledUpload := makeSpoolUpload(t, []byte("x"), 0, 8, 0)
	if _, err := spoolPostFile(canceled, canceledUpload, manager, 8); !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("canceled context error=%v", err)
	}
	upload := makeSpoolUpload(t, []byte("limit"), 0, 16, 0)
	result, err := spoolPostFile(context.Background(), upload, manager, 0)
	if err != nil {
		t.Fatalf("default global limit rejected small file: %v", err)
	}
	if result.length != int64(len("limit")) {
		t.Fatalf("spooled length=%d", result.length)
	}
	if err := result.body.Close(); err != nil {
		t.Fatalf("close spool: %v", err)
	}
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("spool quota leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
	if !errors.Is(classifyPostSpoolAcquire(context.Canceled), ErrStreamingCanceled) || classifyPostSpoolAcquire(ErrSpoolCapacity) != ErrSpoolCapacity {
		t.Fatal("spool acquisition cancellation/capacity classification changed")
	}
	if minPostLimit() != 0 || minPostLimit(9, 4, 7) != 4 {
		t.Fatalf("minPostLimit empty=%d constrained=%d", minPostLimit(), minPostLimit(9, 4, 7))
	}
}

func TestGH353PostSpool_DiskRemoveFailureOwner(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
	checksum := md5.Sum([]byte("abc"))
	upload.checksum = postChecksum{md5: base64.StdEncoding.EncodeToString(checksum[:])}
	directory := t.TempDir()
	manager := NewSpoolManager(8, directory)
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	streamingSpoolOps = original
	streamingSpoolOps.remove = func(path string) error {
		_ = os.Remove(path)
		return errors.New("injected remove")
	}
	result, err := spoolPostFile(context.Background(), upload, manager, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.body.Close(); !errors.Is(err, ErrStreamingSpool) || manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("Close err=%v current=%d", err, manager.(*spoolManager).CurrentBytes())
	}
	if err := result.body.Close(); err != nil {
		t.Fatalf("idempotent Close err=%v", err)
	}
}

func TestGH353PostSpool_PreservesChecksumAlgorithmOnParsedPolicy(t *testing.T) {
	fields := map[string]string{"x-amz-checksum-algorithm": "CRC32"}
	parsed, err := parsePostChecksum(fields)
	if !errors.Is(err, ErrPostChecksumInvalidRequest) {
		t.Fatalf("missing selected checksum error=%v", err)
	}
	fields["x-amz-checksum-crc32"] = "NSRBwg=="
	parsed, err = parsePostChecksum(fields)
	if err != nil || parsed.algorithm != "CRC32" {
		t.Fatalf("checksum=%+v err=%v", parsed, err)
	}
}

func TestGH353PostSpool_ExactInclusiveBounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     []byte
		min, max int64
		want     error
	}{
		{"zero", nil, 0, 0, nil}, {"inclusive minimum", []byte("a"), 1, 1, nil},
		{"inclusive maximum", []byte("abc"), 0, 3, nil}, {"below minimum", nil, 1, 3, ErrPostEntityTooSmall},
		{"one over maximum", []byte("ab"), 0, 1, ErrPostEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upload := makeSpoolUpload(t, tc.data, tc.min, tc.max, 0)
			dir := t.TempDir()
			manager := NewSpoolManager(64, dir)
			result, err := spoolPostFile(context.Background(), upload, manager, 64)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if err != nil {
				got := classifyPostError(err, "/b")
				wantCode, wantStatus := "EntityTooSmall", http.StatusBadRequest
				if errors.Is(tc.want, ErrPostEntityTooLarge) {
					wantCode, wantStatus = "EntityTooLarge", http.StatusRequestEntityTooLarge
				}
				if got.Code != wantCode || got.HTTPStatus != wantStatus || got.Message == "" {
					t.Fatalf("classification=%+v want=%s/%d", got, wantCode, wantStatus)
				}
			}
			if err == nil {
				defer result.body.Close()
				got, readErr := io.ReadAll(result.body)
				if readErr != nil || !bytes.Equal(got, tc.data) || result.length != int64(len(tc.data)) {
					t.Fatalf("body=%q length=%d err=%v", got, result.length, readErr)
				}
			}
			if got := manager.(*spoolManager).CurrentBytes(); got != int64(len(tc.data)) && err == nil || got != 0 && err != nil {
				t.Fatalf("reservation bytes=%d error=%v", got, err)
			}
		})
	}
}

func TestGH353PostSpool_FileNotWholeFormLength(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("file-data"), 0, 32, 300)
	manager := NewSpoolManager(64)
	result, err := spoolPostFile(context.Background(), upload, manager, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer result.body.Close()
	if result.length != int64(len("file-data")) || upload.wire.read <= result.length || upload.wire.read-upload.wire.fileBytes > postFormOverheadLimit {
		t.Fatalf("file=%d wire=%d fileBytes=%d", result.length, upload.wire.read, upload.wire.fileBytes)
	}
}

func TestGH353PostSpool_BoundedReader(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 96*1024)
	upload := makeSpoolUpload(t, data, 0, int64(len(data)), 0)
	bounded := &limitedPostReader{r: upload.fileRead, max: 1}
	upload.fileRead = bounded
	manager := NewSpoolManager(int64(len(data)))
	result, err := spoolPostFile(context.Background(), upload, manager, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer result.body.Close()
	if result.length != int64(len(data)) || bounded.read != int64(len(data)) {
		t.Fatalf("spooled=%d read=%d expected=%d", result.length, bounded.read, len(data))
	}
}

func TestGH353PostSpool_MultiWriteQuotaGrowthPrecedesEveryWrite(t *testing.T) {
	data := bytes.Repeat([]byte("multi-write-body-"), 8*1024)
	upload := makeSpoolUpload(t, data, 0, int64(len(data)), 0)
	directory := t.TempDir()
	manager := NewSpoolManager(int64(len(data)), directory)
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	streamingSpoolOps = original
	writes, written := 0, 0
	streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
		writes++
		wantReserved := int64(written + len(p))
		if got := manager.(*spoolManager).CurrentBytes(); got != wantReserved {
			t.Fatalf("write %d quota=%d want cumulative written+n=%d", writes, got, wantReserved)
		}
		n, err := file.Write(p)
		written += n
		return n, err
	}
	result, err := spoolPostFile(context.Background(), upload, manager, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if writes < 2 || written != len(data) {
		t.Fatalf("writes=%d written=%d want=%d", writes, written, len(data))
	}
	got, err := io.ReadAll(result.body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("spooled body length=%d want=%d err=%v", len(got), len(data), err)
	}
	if err := result.body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := manager.(*spoolManager).CurrentBytes(); got != 0 {
		t.Fatalf("quota after cleanup=%d", got)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("spool entries=%v err=%v", entries, err)
	}
}

func TestGH353PostSpool_ChecksumVectors(t *testing.T) {
	crc32Bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32Bytes, crc32.ChecksumIEEE([]byte("abc")))
	crc32cBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32cBytes, crc32.Checksum([]byte("abc"), crc32.MakeTable(crc32.Castagnoli)))
	md5Bytes := md5.Sum([]byte("abc"))
	cases := []struct {
		name, algorithm, field, digest string
	}{
		{"md5", "", "Content-MD5", base64.StdEncoding.EncodeToString(md5Bytes[:])},
		{"crc32", "CRC32", "x-amz-checksum-crc32", base64.StdEncoding.EncodeToString(crc32Bytes)},
		{"crc32c", "CRC32C", "x-amz-checksum-crc32c", base64.StdEncoding.EncodeToString(crc32cBytes)},
		{"sha1", "SHA1", "x-amz-checksum-sha1", "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="},
		{"sha256", "SHA256", "x-amz-checksum-sha256", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]string{tc.field: tc.digest, "key": "k", "bucket": "b"}
			if tc.algorithm != "" {
				fields["x-amz-checksum-algorithm"] = tc.algorithm
			}
			runChecksumSpoolSuccess(t, fields, []byte("abc"), tc.algorithm, tc.digest)
		})
	}
	t.Run("zero file", func(t *testing.T) {
		emptyMD5 := md5.Sum(nil)
		digest := base64.StdEncoding.EncodeToString(emptyMD5[:])
		runChecksumSpoolSuccess(t, map[string]string{"key": "k", "bucket": "b", "Content-MD5": digest}, nil, "", "")
	})
	if got := base64.StdEncoding.EncodeToString(crc32Bytes); got != "NSRBwg==" {
		t.Fatalf("CRC32 test vector=%q", got)
	}
	if got := base64.StdEncoding.EncodeToString(crc32cBytes); got != "Nks/tw==" {
		t.Fatalf("CRC32C test vector=%q", got)
	}
	for _, fields := range []map[string]string{
		{"x-amz-checksum-algorithm": "CRC64NVME", "x-amz-checksum-crc32": "NSRBwg=="},
		{"Content-MD5": "AB=="},
	} {
		_, err := parsePostChecksum(fields)
		if err == nil {
			t.Errorf("accepted invalid checksum fields %v", fields)
		}
	}
	if _, err := parsePostChecksum(map[string]string{"x-amz-checksum-crc32": "NSRBwg==", "x-amz-checksum-sha1": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="}); !errors.Is(err, ErrPostChecksumInvalidRequest) {
		t.Fatalf("multiple additional checksums error=%v", err)
	}
	if got := classifyPostError(ErrPostChecksumInvalidRequest, "/b"); got.Code != "InvalidRequest" || got.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("checksum selection classification=%+v", got)
	}
	if got := classifyPostError(ErrPostInvalidOption, "/b"); got.Code != "InvalidArgument" || got.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("checksum encoding classification=%+v", got)
	}
	runChecksumSpoolSuccess(t, map[string]string{
		"key": "k", "bucket": "b", "Content-MD5": base64.StdEncoding.EncodeToString(md5Bytes[:]),
		"x-amz-checksum-algorithm": "SHA256", "x-amz-checksum-sha256": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
	}, []byte("abc"), "SHA256", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")
	if _, err := parsePostChecksum(map[string]string{"x-amz-checksum-algorithm": "CRC64NVME", "x-amz-checksum-crc64nvme": "AAAAAA=="}); !errors.Is(err, ErrPostUnsupported) {
		t.Fatalf("CRC64NVME error=%v", err)
	}
	for _, tc := range cases {
		t.Run("mismatch/"+tc.name, func(t *testing.T) {
			decoded, err := base64.StdEncoding.DecodeString(tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			decoded[0] ^= 0xff
			fields := map[string]string{"key": "k", "bucket": "b", tc.field: base64.StdEncoding.EncodeToString(decoded)}
			if tc.algorithm != "" {
				fields["x-amz-checksum-algorithm"] = tc.algorithm
			}
			assertChecksumSpoolFailure(t, fields, []byte("abc"), ErrPostBadDigest, "BadDigest", http.StatusBadRequest)
		})
	}
	emptyMD5 := md5.Sum(nil)
	badMD5Fields := map[string]string{"key": "k", "bucket": "b", "Content-MD5": base64.StdEncoding.EncodeToString(emptyMD5[:])}
	assertChecksumSpoolFailure(t, badMD5Fields, []byte("abc"), ErrPostBadDigest, "BadDigest", http.StatusBadRequest)
	t.Run("unknown valid algorithm is unsupported", func(t *testing.T) {
		_, err := parsePostChecksum(map[string]string{"x-amz-checksum-algorithm": "CRC64NVME", "x-amz-checksum-crc64nvme": "AAAAAA=="})
		if !errors.Is(err, ErrPostUnsupported) || classifyPostError(err, "/b").HTTPStatus != http.StatusNotImplemented {
			t.Fatalf("error=%v S3=%+v", err, classifyPostError(err, "/b"))
		}
	})
	t.Run("supported algorithm mismatch is invalid request", func(t *testing.T) {
		_, err := parsePostChecksum(map[string]string{"x-amz-checksum-algorithm": "CRC32", "x-amz-checksum-crc32c": "Nks/tw=="})
		if !errors.Is(err, ErrPostChecksumInvalidRequest) || classifyPostError(err, "/b").HTTPStatus != http.StatusBadRequest {
			t.Fatalf("error=%v S3=%+v", err, classifyPostError(err, "/b"))
		}
	})
	for _, tc := range []struct {
		name   string
		fields map[string]string
		want   error
	}{
		{"missing selected field", map[string]string{"x-amz-checksum-algorithm": "CRC32"}, ErrPostChecksumInvalidRequest},
		{"multiple values", map[string]string{"x-amz-checksum-crc32": "NSRBwg==", "x-amz-checksum-sha1": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="}, ErrPostChecksumInvalidRequest},
		{"algorithm without digest", map[string]string{"x-amz-checksum-algorithm": "CRC32", "x-amz-checksum-sha1": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="}, ErrPostChecksumInvalidRequest},
		{"empty selected algorithm", map[string]string{"x-amz-checksum-algorithm": "", "x-amz-checksum-crc32": "NSRBwg=="}, ErrPostChecksumInvalidRequest},
		{"case alias duplicate", map[string]string{"x-amz-checksum-crc32": "NSRBwg==", "X-AMZ-CHECKSUM-CRC32": "NSRBwg=="}, ErrPostChecksumInvalidRequest},
		{"empty checksum", map[string]string{"Content-MD5": ""}, ErrPostInvalidOption},
		{"unknown checksum", map[string]string{"x-amz-checksum-nope": "AAAAAA=="}, ErrPostUnsupported},
		{"CRC64NVME field", map[string]string{"x-amz-checksum-crc64nvme": "AAAAAA=="}, ErrPostUnsupported},
		{"base64 newline", map[string]string{"x-amz-checksum-crc32": "NSRBwg==\n"}, ErrPostInvalidOption},
		{"base64 trailing bits", map[string]string{"x-amz-checksum-crc32": "NSRBwh=="}, ErrPostInvalidOption},
		{"base64 unpadded", map[string]string{"x-amz-checksum-crc32": "NSRBwg"}, ErrPostInvalidOption},
		{"base64 wrong length", map[string]string{"x-amz-checksum-crc32": "AAAA"}, ErrPostInvalidOption},
	} {
		t.Run("parse failure/"+tc.name, func(t *testing.T) {
			_, err := parsePostChecksum(tc.fields)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			got := classifyPostError(err, "/b")
			wantCode, wantStatus, wantMessage := "InvalidRequest", http.StatusBadRequest, "Invalid POST checksum selection."
			if errors.Is(tc.want, ErrPostInvalidOption) {
				wantCode, wantMessage = "InvalidArgument", "The specified POST option is invalid."
			} else if errors.Is(tc.want, ErrPostUnsupported) {
				wantCode, wantStatus, wantMessage = "NotImplemented", http.StatusNotImplemented, "The requested POST option is not supported."
			}
			if got.Code != wantCode || got.HTTPStatus != wantStatus || got.Message != wantMessage {
				t.Fatalf("classification=%+v want=%s/%d/%q", got, wantCode, wantStatus, wantMessage)
			}
		})
	}
}

func runChecksumSpoolSuccess(t *testing.T, fields map[string]string, data []byte, algorithm, digest string) {
	t.Helper()
	body, contentType := postMultipart(fields, `Content-Disposition: form-data; name="file"; filename="x"`, string(data))
	request := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	upload, err := parsePostUpload(request, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	upload.checksum, err = parsePostChecksum(upload.fields)
	if err != nil {
		t.Fatalf("checksum parse: %v", err)
	}
	directory := t.TempDir()
	manager := NewSpoolManager(64, directory)
	originalOps := streamingSpoolOps
	defer func() { streamingSpoolOps = originalOps }()
	streamingSpoolOps = originalOps
	writes := 0
	streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
		writes++
		if manager.(*spoolManager).CurrentBytes() < int64(len(p)) {
			t.Fatalf("quota Grow must precede disk write: current=%d write=%d", manager.(*spoolManager).CurrentBytes(), len(p))
		}
		return file.Write(p)
	}
	result, err := spoolPostFile(context.Background(), upload, manager, 64)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	defer result.body.Close()
	spooled, ok := result.body.(*verifiedAWSFile)
	if !ok {
		t.Fatalf("body type=%T", result.body)
	}
	if filepath.Dir(spooled.Name()) != directory {
		t.Fatalf("spool path=%q outside configured directory %q", spooled.Name(), directory)
	}
	info, err := spooled.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("spool mode=%v err=%v", info, err)
	}
	got, err := io.ReadAll(result.body)
	if err != nil || !bytes.Equal(got, data) || result.length != int64(len(data)) || result.body.DecodedLength() != int64(len(data)) {
		t.Fatalf("body=%q length=%d err=%v", got, result.length, err)
	}
	if _, err := result.body.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(result.body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("rewound body=%q err=%v", got, err)
	}
	if len(data) > 0 && writes == 0 {
		t.Fatal("plaintext spool performed no disk writes")
	}
	wantMD5 := md5.Sum(data)
	if result.md5Hex != fmt.Sprintf("%x", wantMD5) {
		t.Fatalf("plaintext md5=%s want=%x", result.md5Hex, wantMD5)
	}
	wantChecksums := map[string]string{}
	if algorithm != "" {
		wantChecksums["x-amz-checksum-"+strings.ToLower(algorithm)] = digest
	}
	if len(result.responseChecksums) != len(wantChecksums) {
		t.Fatalf("response checksums=%v want=%v", result.responseChecksums, wantChecksums)
	}
	for key, value := range wantChecksums {
		if result.responseChecksums[key] != value {
			t.Fatalf("response checksums=%v want=%v", result.responseChecksums, wantChecksums)
		}
	}
}

func assertChecksumSpoolFailure(t *testing.T, fields map[string]string, data []byte, want error, code string, status int) {
	t.Helper()
	body, contentType := postMultipart(fields, `Content-Disposition: form-data; name="file"; filename="x"`, string(data))
	request := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	upload, err := parsePostUpload(request, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	upload.checksum, err = parsePostChecksum(upload.fields)
	if err != nil {
		t.Fatalf("checksum parse: %v", err)
	}
	directory := t.TempDir()
	manager := NewSpoolManager(64, directory)
	result, err := spoolPostFile(context.Background(), upload, manager, 64)
	if !errors.Is(err, want) || result.body != nil || upload.body != nil {
		t.Fatalf("result=%+v err=%v want=%v upload.body=%v", result, err, want, upload.body)
	}
	classified := classifyPostError(err, "/b")
	if classified.Code != code || classified.HTTPStatus != status {
		t.Fatalf("classification=%+v want=%s/%d", classified, code, status)
	}
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("reservation leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
	if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
		t.Fatalf("spool files=%v read error=%v", entries, readErr)
	}
}

func TestGH353PostSpool_CleanupOnAllFailures(t *testing.T) {
	t.Run("aggregate capacity", func(t *testing.T) {
		upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
		manager := NewSpoolManager(2)
		_, err := spoolPostFile(context.Background(), upload, manager, 8)
		if !errors.Is(err, ErrSpoolCapacity) || manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("err=%v bytes=%d", err, manager.(*spoolManager).CurrentBytes())
		}
	})
	t.Run("canceled", func(t *testing.T) {
		upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		manager := NewSpoolManager(8)
		if _, err := spoolPostFile(ctx, upload, manager, 8); !errors.Is(err, ErrStreamingCanceled) || manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("err=%v bytes=%d", err, manager.(*spoolManager).CurrentBytes())
		}
	})
	t.Run("real multipart malformed completion matrix", func(t *testing.T) {
		valid, contentType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, `Content-Disposition: form-data; name="file"; filename="x"`, "abc")
		cases := []struct {
			name string
			body string
			want error
		}{
			{"epilogue", valid + "not-ws", ErrPostFormMalformed},
			{"LF-only framing", strings.ReplaceAll(valid, "\r\n", "\n"), ErrPostIncompleteBody},
			{"truncated closing", strings.TrimSuffix(valid, "--gh353-boundary--\r\n"), ErrPostIncompleteBody},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(tc.body))
				r.Header.Set("Content-Type", contentType)
				upload, err := parsePostUpload(r, 1<<20)
				if err != nil {
					if !errors.Is(err, tc.want) {
						t.Fatalf("parse error=%v want=%v", err, tc.want)
					}
					return
				}
				directory := t.TempDir()
				manager := NewSpoolManager(64, directory)
				result, spoolErr := spoolPostFile(context.Background(), upload, manager, 64)
				if !errors.Is(spoolErr, tc.want) || result.body != nil || upload.body != nil {
					t.Fatalf("result=%+v err=%v want=%v", result, spoolErr, tc.want)
				}
				classified := classifyPostError(spoolErr, "/b")
				wantCode, wantMessage := "IncompleteBody", "The request body is incomplete."
				if errors.Is(tc.want, ErrPostFormMalformed) {
					wantCode, wantMessage = "InvalidRequest", "Invalid POST form."
				}
				if classified.Code != wantCode || classified.HTTPStatus != http.StatusBadRequest || classified.Message != wantMessage {
					t.Fatalf("classification=%+v", classified)
				}
				if manager.(*spoolManager).CurrentBytes() != 0 {
					t.Fatalf("quota leaked: %d", manager.(*spoolManager).CurrentBytes())
				}
				if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
					t.Fatalf("spool files=%v err=%v", entries, readErr)
				}
			})
		}
	})
	t.Run("post-file parts are rejected by spool Finish", func(t *testing.T) {
		valid, contentType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, `Content-Disposition: form-data; name="file"; filename="x"`, "abc")
		for _, tc := range []struct {
			name string
			part string
		}{
			{"second file", "--gh353-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"y\"\r\n\r\nmore-file-data\r\n"},
			{"submit field", "--gh353-boundary\r\nContent-Disposition: form-data; name=\"x-amz-meta-after\"\r\n\r\nvalue\r\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				body := strings.Replace(valid, "--gh353-boundary--\r\n", tc.part+"--gh353-boundary--\r\n", 1)
				r := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(body))
				r.Header.Set("Content-Type", contentType)
				upload, err := parsePostUpload(r, 1<<20)
				if err != nil {
					t.Fatalf("parser returned before spool Finish: %v", err)
				}
				directory := t.TempDir()
				manager := NewSpoolManager(64, directory)
				result, spoolErr := spoolPostFile(context.Background(), upload, manager, 64)
				if !errors.Is(spoolErr, ErrPostFormMalformed) || result.body != nil || upload.body != nil {
					t.Fatalf("result=%+v err=%v", result, spoolErr)
				}
				classified := classifyPostError(spoolErr, "/b")
				if classified.Code != "InvalidRequest" || classified.HTTPStatus != http.StatusBadRequest || classified.Message != "Invalid POST form." {
					t.Fatalf("classification=%+v", classified)
				}
				if manager.(*spoolManager).CurrentBytes() != 0 {
					t.Fatalf("quota leaked: %d", manager.(*spoolManager).CurrentBytes())
				}
				if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
					t.Fatalf("spool files=%v err=%v", entries, readErr)
				}
			})
		}
	})
	t.Run("Content-Length disagreement", func(t *testing.T) {
		goodBody, goodType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, `Content-Disposition: form-data; name="file"; filename="x"`, "abc")
		r := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(goodBody))
		r.Header.Set("Content-Type", goodType)
		r.ContentLength = int64(len(goodBody) + 1)
		upload, err := parsePostUpload(r, 1<<20)
		if err != nil {
			if !errors.Is(err, ErrPostIncompleteBody) {
				t.Fatalf("parse error=%v", err)
			}
			return
		}
		directory := t.TempDir()
		manager := NewSpoolManager(64, directory)
		result, err := spoolPostFile(context.Background(), upload, manager, 64)
		if !errors.Is(err, ErrPostIncompleteBody) || result.body != nil || upload.body != nil || manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("result=%+v err=%v quota=%d", result, err, manager.(*spoolManager).CurrentBytes())
		}
		if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
			t.Fatalf("files=%v err=%v", entries, readErr)
		}
	})
	t.Run("valid whitespace epilogue overhead is rejected at Finish", func(t *testing.T) {
		body, contentType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, `Content-Disposition: form-data; name="file"; filename="x"`, "x")
		body += strings.Repeat(" ", int(postFormOverheadLimit))
		r := httptest.NewRequest(http.MethodPost, "/b", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		upload, err := parsePostUpload(r, 1<<20)
		if err != nil {
			t.Fatalf("parse failed before spool: %v", err)
		}
		directory := t.TempDir()
		manager := NewSpoolManager(64, directory)
		result, spoolErr := spoolPostFile(context.Background(), upload, manager, 64)
		if !errors.Is(spoolErr, ErrPostEntityTooLarge) || result.body != nil || upload.body != nil || !upload.fileCounter.eof {
			t.Fatalf("result=%+v err=%v fileEOF=%t", result, spoolErr, upload.fileCounter.eof)
		}
		classified := classifyPostError(spoolErr, "/b")
		if classified.Code != "EntityTooLarge" || classified.HTTPStatus != http.StatusRequestEntityTooLarge || classified.Message != "The request exceeds the permitted payload size." {
			t.Fatalf("classification=%+v", classified)
		}
		if manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("quota leaked: %d", manager.(*spoolManager).CurrentBytes())
		}
		if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
			t.Fatalf("spool files=%v err=%v", entries, readErr)
		}
	})
	t.Run("raw wire cap is reported during file spooling", func(t *testing.T) {
		largeHeader := "Content-Disposition: form-data; name=\"file\"; filename=\"x\"\r\nX-Padding: " + strings.Repeat("p", 21*1024)
		body, contentType := postMultipart(map[string]string{"key": "k", "bucket": "b"}, largeHeader, strings.Repeat("f", 128*1024))
		for _, chunk := range []int{1, 7, 64} {
			t.Run(fmt.Sprintf("chunk-%d", chunk), func(t *testing.T) {
				counted := &limitedPostReader{r: strings.NewReader(body), max: chunk}
				r := httptest.NewRequest(http.MethodPost, "/b", nil)
				r.Header.Set("Content-Type", contentType)
				r.Body = io.NopCloser(counted)
				r.ContentLength = -1
				upload, err := parsePostUpload(r, 64*1024)
				if err != nil {
					t.Fatalf("parse failed before spool: %v", err)
				}
				if upload.fileCounter.eof || upload.wire.read-upload.wire.fileBytes > postBeforeFileLimit || upload.wire.fileBytes != 0 {
					t.Fatalf("parser consumed file or exceeded pre-auth allowance: fileEOF=%t wire=%d file=%d", upload.fileCounter.eof, upload.wire.read, upload.wire.fileBytes)
				}
				var fileReadErr error
				upload.fileRead = &recordPostReadError{reader: upload.fileRead, record: func(err error) {
					if errors.Is(err, ErrPostEntityTooLarge) {
						fileReadErr = err
					}
				}}
				directory := t.TempDir()
				manager := NewSpoolManager(128*1024, directory)
				result, spoolErr := spoolPostFile(context.Background(), upload, manager, 128*1024)
				if spoolErr != ErrPostEntityTooLarge || result.body != nil || upload.body != nil {
					t.Fatalf("result=%+v err=%v", result, spoolErr)
				}
				if fileReadErr != ErrPostEntityTooLarge || upload.fileCounter.eof {
					t.Fatalf("file read error=%v file EOF=%t", fileReadErr, upload.fileCounter.eof)
				}
				classified := classifyPostError(spoolErr, "/b")
				if classified.Code != "EntityTooLarge" || classified.HTTPStatus != http.StatusRequestEntityTooLarge || classified.Message != "The request exceeds the permitted payload size." {
					t.Fatalf("classification=%+v", classified)
				}
				if manager.(*spoolManager).CurrentBytes() != 0 {
					t.Fatalf("quota leaked: %d", manager.(*spoolManager).CurrentBytes())
				}
				if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
					t.Fatalf("spool files=%v err=%v", entries, readErr)
				}
			})
		}
	})
	t.Run("disk operation failures", func(t *testing.T) {
		for _, stage := range []string{"create", "chmod", "write", "short-write", "seek"} {
			t.Run(stage, func(t *testing.T) {
				upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
				directory := t.TempDir()
				manager := NewSpoolManager(8, directory)
				original := streamingSpoolOps
				t.Cleanup(func() { streamingSpoolOps = original })
				streamingSpoolOps = original
				switch stage {
				case "create":
					streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("injected") }
				case "chmod":
					streamingSpoolOps.chmod = func(*os.File, os.FileMode) error { return errors.New("injected") }
				case "write":
					streamingSpoolOps.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected") }
				case "short-write":
					streamingSpoolOps.write = func(f *os.File, data []byte) (int, error) { n, _ := f.Write(data); return n - 1, nil }
				case "seek":
					streamingSpoolOps.seek = func(*os.File, int64, int) (int64, error) { return 0, errors.New("injected") }
				}
				_, err := spoolPostFile(context.Background(), upload, manager, 8)
				wantErr := error(ErrStreamingSpool)
				if !errors.Is(err, wantErr) || manager.(*spoolManager).CurrentBytes() != 0 {
					t.Fatalf("err=%v bytes=%d", err, manager.(*spoolManager).CurrentBytes())
				}
				entries, readErr := os.ReadDir(directory)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("stage=%s leaked spool entries=%v err=%v", stage, entries, readErr)
				}
			})
		}
	})
	t.Run("verified file close failure", func(t *testing.T) {
		directory := t.TempDir()
		manager := NewSpoolManager(8, directory)
		reservation, err := manager.Acquire(context.Background(), 3, 8)
		if err != nil {
			t.Fatal(err)
		}
		file, err := streamingSpoolOps.createTemp(directory, "s3gw-post-close-*")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		body := &verifiedAWSFile{File: file, length: 3, path: path, reservation: reservation}
		original := streamingSpoolOps
		t.Cleanup(func() { streamingSpoolOps = original })
		streamingSpoolOps = original
		streamingSpoolOps.close = func(f *os.File) error { _ = f.Close(); return errors.New("injected close") }
		if err := body.Close(); !errors.Is(err, ErrStreamingSpool) || manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("Close err=%v current=%d", err, manager.(*spoolManager).CurrentBytes())
		}
		if err := body.Close(); err != nil {
			t.Fatalf("idempotent Close err=%v", err)
		}
	})
	t.Run("verified file remove failure", func(t *testing.T) {
		directory := t.TempDir()
		manager := NewSpoolManager(8, directory)
		reservation, err := manager.Acquire(context.Background(), 3, 8)
		if err != nil {
			t.Fatal(err)
		}
		file, err := streamingSpoolOps.createTemp(directory, "s3gw-post-remove-*")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		body := &verifiedAWSFile{File: file, length: 3, path: path, reservation: reservation}
		original := streamingSpoolOps
		t.Cleanup(func() { streamingSpoolOps = original })
		streamingSpoolOps = original
		streamingSpoolOps.remove = func(path string) error { _ = os.Remove(path); return errors.New("injected remove") }
		if err := body.Close(); !errors.Is(err, ErrStreamingSpool) || manager.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("Close err=%v current=%d", err, manager.(*spoolManager).CurrentBytes())
		}
	})
}

func TestGH353PostSpool_ReadCancellationBeforePersist(t *testing.T) {
	for _, tc := range []struct {
		name string
		eof  bool
	}{
		{"data", false}, {"data plus EOF", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			manager := NewSpoolManager(16, directory)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plain, err := manager.Acquire(context.Background(), 2, 2)
			if err != nil {
				t.Fatal(err)
			}
			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			reads := 0
			streamingSpoolOps.readRequestBody = func(r io.Reader, p []byte) (int, error) {
				reads++
				if reads == 1 {
					copy(p, "ab")
					return 2, nil
				}
				cancel()
				copy(p, "chunk")
				if tc.eof {
					return 5, io.EOF
				}
				return 5, nil
			}
			writes := 0
			written := 0
			streamingSpoolOps.write = func(f *os.File, p []byte) (int, error) { writes++; written += len(p); return f.Write(p) }
			_, err = spoolPostCiphertextLimit(ctx, strings.NewReader("ignored"), manager, 8)
			if !errors.Is(err, ErrStreamingCanceled) || writes != 1 || written != 2 || manager.(*spoolManager).CurrentBytes() != 2 {
				t.Fatalf("err=%v writes=%d written=%d quota=%d", err, writes, written, manager.(*spoolManager).CurrentBytes())
			}
			if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
				t.Fatalf("cipher files=%v err=%v", entries, readErr)
			}
			plain.Release()
			if manager.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("plaintext reservation leaked: %d", manager.(*spoolManager).CurrentBytes())
			}
		})
	}
	t.Run("plaintext reader cancellation", func(t *testing.T) {
		for _, eof := range []bool{false, true} {
			upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
			ctx, cancel := context.WithCancel(context.Background())
			manager := NewSpoolManager(16, t.TempDir())
			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			reads := 0
			streamingSpoolOps.readRequestBody = func(_ io.Reader, p []byte) (int, error) {
				reads++
				if reads == 1 {
					copy(p, "ab")
					return 2, nil
				}
				cancel()
				copy(p, "xyz")
				if eof {
					return 3, io.EOF
				}
				return 3, nil
			}
			writes := 0
			written := 0
			streamingSpoolOps.write = func(f *os.File, p []byte) (int, error) { writes++; written += len(p); return f.Write(p) }
			_, err := spoolPostFile(ctx, upload, manager, 8)
			if !errors.Is(err, ErrStreamingCanceled) || writes != 1 || written != 2 || manager.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("eof=%v err=%v writes=%d written=%d quota=%d", eof, err, writes, written, manager.(*spoolManager).CurrentBytes())
			}
			cancel()
		}
	})
}

func TestGH353PostSpool_ReaderErrStreamingCanceledPreserved(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("unpersisted"), 0, 32, 0)
	directory := t.TempDir()
	manager := NewSpoolManager(32, directory)
	wrapped := fmt.Errorf("reader stopped: %w", ErrStreamingCanceled)
	upload.fileRead = errorPostRead{data: []byte("unpersisted"), err: wrapped}
	writes := 0
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	streamingSpoolOps = original
	streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
		writes++
		return file.Write(p)
	}
	result, err := spoolPostFile(context.Background(), upload, manager, 32)
	if err != ErrStreamingCanceled || result.body != nil || upload.body != nil {
		t.Fatalf("result=%+v err=%v want sentinel identity %v", result, err, ErrStreamingCanceled)
	}
	if !errors.Is(err, ErrStreamingCanceled) {
		t.Fatalf("error %v does not preserve cancellation sentinel", err)
	}
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("quota leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
	if writes != 0 {
		t.Fatalf("canceled reader data writes=%d want 0", writes)
	}
	if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
		t.Fatalf("spool files=%v err=%v", entries, readErr)
	}
}

type errorPostRead struct {
	data []byte
	err  error
}

func (r errorPostRead) Read(p []byte) (int, error) { return copy(p, r.data), r.err }

type scriptedPostRead struct {
	reads []struct {
		data []byte
		err  error
	}
	next int
}

func (r *scriptedPostRead) Read(p []byte) (int, error) {
	if r.next >= len(r.reads) {
		return 0, io.EOF
	}
	read := r.reads[r.next]
	r.next++
	return copy(p, read.data), read.err
}

type growCountingSpoolManager struct {
	base     SpoolManager
	grows    int
	acquires int
}

func (m *growCountingSpoolManager) Acquire(ctx context.Context, n, limit int64) (SpoolReservation, error) {
	m.acquires++
	reservation, err := m.base.Acquire(ctx, n, limit)
	if err != nil {
		return nil, err
	}
	return &growCountingReservation{SpoolReservation: reservation, manager: m}, nil
}

type growCountingReservation struct {
	SpoolReservation
	manager *growCountingSpoolManager
}

func (r *growCountingReservation) Grow(n int64) error {
	r.manager.grows++
	return r.SpoolReservation.Grow(n)
}

func TestGH353PostSpool_CiphertextReaderErrStreamingCanceledPreserved(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reads []struct {
			data []byte
			err  error
		}
		wantWrites    int
		wantGrows     int
		wantWriteData string
	}{
		{name: "canceled chunk only", reads: []struct {
			data []byte
			err  error
		}{{[]byte("canceled"), fmt.Errorf("reader stopped: %w", ErrStreamingCanceled)}}},
		{name: "prior chunk then canceled chunk", reads: []struct {
			data []byte
			err  error
		}{{[]byte("prior"), nil}, {[]byte("canceled"), fmt.Errorf("reader stopped: %w", ErrStreamingCanceled)}}, wantWrites: 1, wantGrows: 1, wantWriteData: "prior"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			base := NewSpoolManager(64, directory)
			plainReservation, err := base.Acquire(context.Background(), 4, 4)
			if err != nil {
				t.Fatal(err)
			}
			plainFile, err := os.CreateTemp(directory, "held-plaintext-*")
			if err != nil {
				plainReservation.Release()
				t.Fatal(err)
			}
			if _, err := plainFile.Write([]byte("held")); err != nil {
				_ = plainFile.Close()
				_ = os.Remove(plainFile.Name())
				plainReservation.Release()
				t.Fatal(err)
			}
			plain := &verifiedAWSFile{File: plainFile, length: 4, path: plainFile.Name(), reservation: plainReservation}
			manager := &growCountingSpoolManager{base: base}
			reads := make([]struct {
				data []byte
				err  error
			}, len(tc.reads))
			copy(reads, tc.reads)
			reader := &scriptedPostRead{reads: reads}
			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			var written strings.Builder
			writes := 0
			streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
				writes++
				written.Write(p)
				return file.Write(p)
			}
			if tc.wantWrites == 0 {
				streamingSpoolOps.write = func(*os.File, []byte) (int, error) {
					t.Error("canceled ciphertext bytes reached disk write")
					return 0, errors.New("unexpected canceled write")
				}
			}
			_, err = spoolPostCiphertextLimit(context.Background(), reader, manager, 32)
			if err != ErrStreamingCanceled || !errors.Is(err, ErrStreamingCanceled) {
				t.Fatalf("err=%v want cancellation sentinel identity %v", err, ErrStreamingCanceled)
			}
			if writes != tc.wantWrites || manager.grows != tc.wantGrows || manager.acquires != 1 || written.String() != tc.wantWriteData {
				t.Fatalf("writes=%d grows=%d acquires=%d written=%q; want writes=%d grows=%d one acquire data=%q", writes, manager.grows, manager.acquires, written.String(), tc.wantWrites, tc.wantGrows, tc.wantWriteData)
			}
			if got := base.(*spoolManager).CurrentBytes(); got != 4 {
				t.Fatalf("cipher cleanup changed held plaintext quota: %d", got)
			}
			if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(plainFile.Name()) {
				t.Fatalf("cipher cleanup changed independently-owned plaintext spool: files=%v err=%v", entries, readErr)
			}
			if err := plain.Close(); err != nil {
				t.Fatal(err)
			}
			if got := base.(*spoolManager).CurrentBytes(); got != 0 {
				t.Fatalf("plaintext reservation leaked: %d", got)
			}
			if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
				t.Fatalf("held plaintext cleanup files=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestGH353PostSpool_PlaintextReaderErrStreamingCanceledBeforePersist(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reads []struct {
			data []byte
			err  error
		}
		wantWrites    int
		wantGrows     int
		wantWriteData string
	}{
		{name: "canceled chunk only", reads: []struct {
			data []byte
			err  error
		}{{[]byte("canceled"), fmt.Errorf("reader stopped: %w", ErrStreamingCanceled)}}},
		{name: "prior chunk then canceled chunk", reads: []struct {
			data []byte
			err  error
		}{{[]byte("prior"), nil}, {[]byte("canceled"), fmt.Errorf("reader stopped: %w", ErrStreamingCanceled)}}, wantWrites: 1, wantGrows: 1, wantWriteData: "prior"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			base := NewSpoolManager(64, directory)
			manager := &growCountingSpoolManager{base: base}
			upload := makeSpoolUpload(t, []byte("unused"), 0, 32, 0)
			reads := make([]struct {
				data []byte
				err  error
			}, len(tc.reads))
			copy(reads, tc.reads)
			upload.fileRead = &scriptedPostRead{reads: reads}
			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			var written strings.Builder
			writes := 0
			streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
				writes++
				written.Write(p)
				return file.Write(p)
			}
			if tc.wantWrites == 0 {
				streamingSpoolOps.write = func(*os.File, []byte) (int, error) {
					t.Error("canceled plaintext bytes reached disk write")
					return 0, errors.New("unexpected canceled write")
				}
			}
			result, err := spoolPostFile(context.Background(), upload, manager, 32)
			if err != ErrStreamingCanceled || !errors.Is(err, ErrStreamingCanceled) || result.body != nil || upload.body != nil {
				t.Fatalf("result=%+v err=%v want cancellation sentinel identity %v", result, err, ErrStreamingCanceled)
			}
			if writes != tc.wantWrites || manager.grows != tc.wantGrows || manager.acquires != 1 || written.String() != tc.wantWriteData {
				t.Fatalf("writes=%d grows=%d acquires=%d written=%q; want writes=%d grows=%d one acquire data=%q", writes, manager.grows, manager.acquires, written.String(), tc.wantWrites, tc.wantGrows, tc.wantWriteData)
			}
			if got := base.(*spoolManager).CurrentBytes(); got != 0 {
				t.Fatalf("quota leaked: %d", got)
			}
			if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 0 {
				t.Fatalf("plaintext spool files=%v err=%v", entries, readErr)
			}
		})
	}
}

type recordPostReadError struct {
	reader io.Reader
	record func(error)
}

func (r *recordPostReadError) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if r.record != nil {
		r.record(err)
	}
	return n, err
}

func TestGH353PostSpool_LiveLimitSnapshot(t *testing.T) {
	limits := NewSpoolLimitSource(SpoolLimits{Global: 4, Part: 1})
	captured := limits.Limits()
	upload := makeSpoolUpload(t, []byte("12345"), 0, 20, 0)
	upload.limitSnapshot = captured
	limits.Set(SpoolLimits{Global: 100, Part: 100})
	manager := NewSpoolManager(100)
	_, err := spoolPostFile(context.Background(), upload, manager, 100)
	if !errors.Is(err, ErrPostEntityTooLarge) || manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("err=%v current=%d captured=%+v currentLimits=%+v", err, manager.(*spoolManager).CurrentBytes(), captured, limits.Limits())
	}
}

func TestGH353PostSpool_CiphertextQuotaLengthAndRetry(t *testing.T) {
	directory := t.TempDir()
	manager := NewSpoolManager(8, directory)
	plainReservation, err := manager.Acquire(context.Background(), 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := spoolPostCiphertext(context.Background(), strings.NewReader("12345"), manager)
	if err != nil {
		plainReservation.Release()
		t.Fatalf("cipher spool: %v", err)
	}
	if got := manager.(*spoolManager).CurrentBytes(); got != 8 || cipher.DecodedLength() != 5 {
		t.Fatalf("aggregate=%d cipher length=%d", got, cipher.DecodedLength())
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := cipher.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(cipher)
		if err != nil || string(body) != "12345" {
			t.Fatalf("attempt=%d body=%q err=%v", attempt, body, err)
		}
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
	plainReservation.Release()
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("aggregate reservation leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("temp entries=%v err=%v", entries, err)
	}
	if entries, _ := filepath.Glob(filepath.Join(directory, "s3gw-post-*")); len(entries) != 0 {
		t.Fatalf("spool files leaked: %v", entries)
	}
	t.Run("limit sentinel", func(t *testing.T) {
		limited := NewSpoolManager(16, t.TempDir())
		if _, err := spoolPostCiphertextLimit(context.Background(), strings.NewReader("1234567"), limited, 6); !errors.Is(err, ErrPostEntityTooLarge) || limited.(*spoolManager).CurrentBytes() != 0 {
			t.Fatalf("error=%v current=%d", err, limited.(*spoolManager).CurrentBytes())
		}
	})
}

func TestGH353PostSpool_SimultaneousPlaintextAndCiphertextOwnership(t *testing.T) {
	directory := t.TempDir()
	manager := NewSpoolManager(16, directory)
	upload := makeSpoolUpload(t, []byte("plain"), 0, 8, 0)
	plain, err := spoolPostFile(context.Background(), upload, manager, 8)
	if err != nil {
		t.Fatal(err)
	}
	originalOps := streamingSpoolOps
	defer func() { streamingSpoolOps = originalOps }()
	streamingSpoolOps = originalOps
	streamingSpoolOps.write = func(file *os.File, p []byte) (int, error) {
		if manager.(*spoolManager).CurrentBytes() < int64(len("plain")+len(p)) {
			t.Fatalf("cipher quota Grow must precede write: current=%d len=%d", manager.(*spoolManager).CurrentBytes(), len(p))
		}
		return file.Write(p)
	}
	cipher, err := spoolPostCiphertextLimit(context.Background(), strings.NewReader("cipher"), manager, 8)
	if err != nil {
		_ = plain.body.Close()
		t.Fatal(err)
	}
	if manager.(*spoolManager).CurrentBytes() != int64(len("plain")+len("cipher")) {
		t.Fatalf("aggregate reservation=%d", manager.(*spoolManager).CurrentBytes())
	}
	if plain.body.DecodedLength() != int64(len("plain")) || cipher.DecodedLength() != int64(len("cipher")) {
		t.Fatalf("plain length=%d cipher length=%d", plain.body.DecodedLength(), cipher.DecodedLength())
	}
	for label, body := range map[string]verifiedAWSBody{"plaintext": plain.body, "ciphertext": cipher} {
		file, ok := body.(*verifiedAWSFile)
		if !ok {
			t.Fatalf("%s body type=%T", label, body)
		}
		if filepath.Dir(file.Name()) != directory {
			t.Fatalf("%s spool outside configured directory: %s", label, file.Name())
		}
		info, statErr := file.Stat()
		if statErr != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%v err=%v", label, info, statErr)
		}
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.(*spoolManager).CurrentBytes() != int64(len("plain")) {
		t.Fatalf("cipher close released wrong reservation: %d", manager.(*spoolManager).CurrentBytes())
	}
	if _, err := plain.body.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(plain.body); err != nil || string(got) != "plain" {
		t.Fatalf("plaintext body=%q err=%v", got, err)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("plaintext ownership leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("spool files=%v err=%v", entries, err)
	}
}

func TestGH353PostSpool_CiphertextFailureCleanup(t *testing.T) {
	for _, stage := range []string{"aggregate", "create", "chmod", "write", "short-write", "seek", "read"} {
		t.Run(stage, func(t *testing.T) {
			directory := t.TempDir()
			manager := NewSpoolManager(4, directory)
			reader := io.Reader(strings.NewReader("abc"))
			if stage == "aggregate" {
				manager = NewSpoolManager(2, t.TempDir())
			}
			if stage == "read" {
				reader = postFailReader{}
			}
			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			switch stage {
			case "create":
				streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("injected") }
			case "chmod":
				streamingSpoolOps.chmod = func(*os.File, os.FileMode) error { return errors.New("injected") }
			case "write":
				streamingSpoolOps.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected") }
			case "short-write":
				streamingSpoolOps.write = func(f *os.File, data []byte) (int, error) { n, _ := f.Write(data); return n - 1, nil }
			case "seek":
				streamingSpoolOps.seek = func(*os.File, int64, int) (int64, error) { return 0, errors.New("injected") }
			}
			_, err := spoolPostCiphertextLimit(context.Background(), reader, manager, 8)
			if err == nil || manager.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("stage=%s err=%v current=%d", stage, err, manager.(*spoolManager).CurrentBytes())
			}
			entries, readErr := os.ReadDir(directory)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("stage=%s leaked spool entries=%v err=%v", stage, entries, readErr)
			}
		})
	}
}

func TestGH353PostSpool_UploadCloseOwnsPlaintextReservation(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
	manager := NewSpoolManager(8)
	result, err := spoolPostFile(context.Background(), upload, manager, 8)
	if err != nil {
		t.Fatal(err)
	}
	if manager.(*spoolManager).CurrentBytes() != 3 {
		t.Fatalf("reserved bytes before close=%d", manager.(*spoolManager).CurrentBytes())
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	if err := result.body.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("plaintext reservation leaked: %d", manager.(*spoolManager).CurrentBytes())
	}
}

func TestGH353PostSpool_ExclusiveDeadline(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
	upload.deadline = time.Now().Add(-time.Nanosecond)
	manager := NewSpoolManager(8)
	if _, err := spoolPostFile(context.Background(), upload, manager, 8); !errors.Is(err, ErrRequestExpired) || manager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("err=%v current=%d", err, manager.(*spoolManager).CurrentBytes())
	}
}

type failPostSpoolManager struct {
	reservation *failPostSpoolReservation
}

func (m *failPostSpoolManager) Acquire(context.Context, int64, int64) (SpoolReservation, error) {
	m.reservation = &failPostSpoolReservation{}
	return m.reservation, nil
}

type failPostSpoolReservation struct{ released bool }

func (r *failPostSpoolReservation) Grow(int64) error { return ErrSpoolCapacity }
func (r *failPostSpoolReservation) Release()         { r.released = true }

func TestGH353PostSpool_RequestReaderAndQuotaFailure(t *testing.T) {
	upload := makeSpoolUpload(t, []byte("abc"), 0, 8, 0)
	manager := &failPostSpoolManager{}
	if _, err := spoolPostFile(context.Background(), upload, manager, 8); !errors.Is(err, ErrSpoolCapacity) || manager.reservation == nil || !manager.reservation.released {
		t.Fatalf("quota grow error=%v reservation=%+v", err, manager.reservation)
	}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		reader io.Reader
		want   error
	}{
		{"nil context", nil, strings.NewReader("x"), ErrPostFormMalformed},
		{"nil reader", context.Background(), nil, ErrPostFormMalformed},
		{"canceled", canceledPostContext(), strings.NewReader("x"), ErrStreamingCanceled},
		{"read error", context.Background(), postFailReader{}, ErrStreamingSpool},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewSpoolManager(16, t.TempDir())
			_, err := spoolPostCiphertextLimit(tc.ctx, tc.reader, m, 8)
			if !errors.Is(err, tc.want) || m.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("err=%v want=%v current=%d", err, tc.want, m.(*spoolManager).CurrentBytes())
			}
		})
	}
}

type postFailReader struct{}

func (postFailReader) Read([]byte) (int, error) { return 0, errors.New("injected read failure") }

func canceledPostContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
