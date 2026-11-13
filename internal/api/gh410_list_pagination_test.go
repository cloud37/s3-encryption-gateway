package api

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// gh410ListClient models opaque backend tokens and counts common prefixes as
// entries in the backend page limit, as S3 does.
type gh410ListClient struct {
	s3.Client
	keys      []string
	failToken string
	repeat    bool
	noToken   bool
	oversize  bool
	requests  []s3.ListOptions
}

func (c *gh410ListClient) ListObjects(_ context.Context, _, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	c.requests = append(c.requests, opts)
	if opts.ContinuationToken != "" && opts.ContinuationToken == c.failToken {
		return s3.ListResult{}, fmt.Errorf("backend page unavailable")
	}
	type entry struct {
		key      string
		isPrefix bool
	}
	entries := make([]entry, 0, len(c.keys))
	seen := make(map[string]bool)
	for _, key := range c.keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		name, isPrefix := key, false
		if opts.Delimiter != "" {
			if i := strings.Index(key[len(prefix):], opts.Delimiter); i >= 0 {
				name = key[:len(prefix)+i+len(opts.Delimiter)]
				isPrefix = true
			}
		}
		if (opts.ContinuationToken == "" && name <= opts.StartAfter) || seen[name] {
			continue
		}
		seen[name] = true
		entries = append(entries, entry{name, isPrefix})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	start := 0
	if opts.ContinuationToken != "" {
		if !strings.HasPrefix(opts.ContinuationToken, "opaque-") {
			return s3.ListResult{}, fmt.Errorf("invalid continuation token")
		}
		last, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(opts.ContinuationToken, "opaque-"))
		if err != nil {
			return s3.ListResult{}, fmt.Errorf("invalid continuation token")
		}
		start = sort.Search(len(entries), func(i int) bool { return entries[i].key > string(last) })
	}
	end := min(start+int(opts.MaxKeys), len(entries))
	result := s3.ListResult{IsTruncated: end < len(entries)}
	for _, e := range entries[start:end] {
		if e.isPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, e.key)
		} else {
			result.Objects = append(result.Objects, s3.ObjectInfo{Key: e.key, Size: 1})
		}
	}
	if result.IsTruncated {
		result.NextContinuationToken = "opaque-" + base64.RawURLEncoding.EncodeToString([]byte(entries[end-1].key))
		if c.repeat && opts.ContinuationToken != "" {
			result.NextContinuationToken = opts.ContinuationToken
		}
		if c.noToken {
			result.NextContinuationToken = ""
		}
	}
	if c.oversize && opts.ContinuationToken != "" {
		result.Objects = append(result.Objects, s3.ObjectInfo{Key: "extra"})
	}
	return result, nil
}

type gh410ListXML struct {
	IsTruncated bool   `xml:"IsTruncated"`
	NextToken   string `xml:"NextContinuationToken"`
	NextMarker  string `xml:"NextMarker"`
	Contents    []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	Prefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

func gh410Router(client s3.Client) *mux.Router {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	h := NewHandler(client, nil, logger, getTestMetrics())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	return router
}

func TestGH410_ListPaginationPreservesObjectsAndPrefixes(t *testing.T) {
	tests := []struct {
		name              string
		keys              []string
		delimiter         string
		maxKeys           int
		objects, prefixes []string
	}{
		{"trimmed final page", []string{"a", "a.mpu-manifest", "b", "c", "d"}, "", 3, []string{"a", "b", "c", "d"}, nil},
		{"trimmed nonfinal page", []string{"a", "a.mpu-manifest", "b", "c", "d", "e", "f", "g"}, "", 3, []string{"a", "b", "c", "d", "e", "f", "g"}, nil},
		{"exact final page", []string{"a", "a.mpu-manifest", "b", "c"}, "", 3, []string{"a", "b", "c"}, nil},
		{"manifest only pages", []string{"a.mpu-manifest", "b.mpu-manifest", "c.mpu-manifest", "d", "e"}, "", 1, []string{"d", "e"}, nil},
		{"delimiter prefixes", []string{"a", "a.mpu-manifest", "b/one", "c/two", "d", "e/three", "f"}, "/", 2, []string{"a", "d", "f"}, []string{"b/", "c/", "e/"}},
		{"only hidden", []string{"a.mpu-manifest", "b.mpu-manifest"}, "", 1, nil, nil},
	}
	for _, tc := range tests {
		for _, version := range []string{"1", "2"} {
			t.Run(tc.name+"/v"+version, func(t *testing.T) {
				client := &gh410ListClient{Client: newMockS3Client(), keys: tc.keys}
				router := gh410Router(client)
				query := url.Values{"max-keys": {strconv.Itoa(tc.maxKeys)}}
				if version == "2" {
					query.Set("list-type", "2")
				}
				if tc.delimiter != "" {
					query.Set("delimiter", tc.delimiter)
				}
				var objects, prefixes []string
				seenTokens := map[string]bool{}
				for page := 0; page < 20; page++ {
					w := httptest.NewRecorder()
					router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bucket?"+query.Encode(), nil))
					if w.Code != http.StatusOK {
						t.Fatalf("page %d status=%d body=%s", page, w.Code, w.Body.String())
					}
					var result gh410ListXML
					if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if len(result.Contents)+len(result.Prefixes) > tc.maxKeys {
						t.Fatalf("page exceeds max-keys: %s", w.Body.String())
					}
					for _, item := range result.Contents {
						objects = append(objects, item.Key)
					}
					for _, item := range result.Prefixes {
						prefixes = append(prefixes, item.Prefix)
					}
					if tc.name == "exact final page" && page == 0 && result.IsTruncated {
						t.Fatalf("fully consumed final page marked truncated: %s", w.Body.String())
					}
					if !result.IsTruncated {
						break
					}
					token, field := result.NextToken, "continuation-token"
					if version == "1" {
						token, field = result.NextMarker, "marker"
					}
					if token == "" || seenTokens[token] {
						t.Fatalf("page %d has missing or repeated %s: %s", page, field, w.Body.String())
					}
					seenTokens[token] = true
					query.Set(field, token)
					if page == 19 {
						t.Fatal("pagination did not terminate")
					}
				}
				if !reflect.DeepEqual(objects, tc.objects) || !reflect.DeepEqual(prefixes, tc.prefixes) {
					t.Fatalf("objects=%v prefixes=%v; want objects=%v prefixes=%v", objects, prefixes, tc.objects, tc.prefixes)
				}
			})
		}
	}
}

func TestGH410_ListPaginationRefillErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failToken string
		repeat    bool
		noToken   bool
		oversize  bool
	}{
		{"backend error", "opaque-YS5tcHUtbWFuaWZlc3Q", false, false, false},
		{"repeated token", "", true, false, false},
		{"missing token", "", false, true, false},
		{"oversized page", "", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &gh410ListClient{Client: newMockS3Client(), keys: []string{"a.mpu-manifest", "b.mpu-manifest", "c.mpu-manifest", "d"}, failToken: tc.failToken, repeat: tc.repeat, noToken: tc.noToken, oversize: tc.oversize}
			w := httptest.NewRecorder()
			gh410Router(client).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bucket?list-type=2&max-keys=1", nil))
			if w.Code == http.StatusOK {
				t.Fatalf("incomplete listing returned success: %s", w.Body.String())
			}
			if len(client.requests) > 4 {
				t.Fatalf("pagination failed to stop: %d requests", len(client.requests))
			}
		})
	}
}
