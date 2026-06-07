package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// mockAuditClient is a read-only mock for testing audit commands.
// It satisfies AuditClient using in-memory metadata and data maps.
type mockAuditClient struct {
	mu       sync.RWMutex
	objects  map[string][]byte           // key -> ciphertext body
	metadata map[string]map[string]string // key -> metadata
	fail     map[string]error             // specific error injections
}

func newMockAuditClient() *mockAuditClient {
	return &mockAuditClient{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
		fail:     make(map[string]error),
	}
}

func (m *mockAuditClient) addObject(key string, body []byte, meta map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = body
	if meta != nil {
		m.metadata[key] = meta
	} else {
		m.metadata[key] = make(map[string]string)
	}
}

func (m *mockAuditClient) setError(action, key string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail[action+":"+key] = err
}

func (m *mockAuditClient) HeadObject(_ context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fullKey := bucket + "/" + key
	if err := m.fail["head:"+fullKey]; err != nil {
		return nil, err
	}
	meta, ok := m.metadata[fullKey]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	result := make(map[string]string, len(meta))
	for k, v := range meta {
		result[k] = v
	}
	return result, nil
}

func (m *mockAuditClient) GetObject(_ context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fullKey := bucket + "/" + key
	if err := m.fail["get:"+fullKey]; err != nil {
		return nil, nil, err
	}
	data, ok := m.objects[fullKey]
	if !ok {
		return nil, nil, fmt.Errorf("not found")
	}
	meta := m.metadata[fullKey]
	if meta == nil {
		meta = make(map[string]string)
	}
	// Apply range header if present
	if rangeHeader != nil && *rangeHeader != "" {
		var start, end int64
		if n, _ := fmt.Sscanf(*rangeHeader, "bytes=%d-%d", &start, &end); n == 2 {
			if int(start) < len(data) {
				if int(end) >= len(data) {
					end = int64(len(data) - 1)
				}
				data = data[start : end+1]
			} else {
				data = nil
			}
		}
	}
	resultMeta := make(map[string]string, len(meta))
	for k, v := range meta {
		resultMeta[k] = v
	}
	return io.NopCloser(bytes.NewReader(data)), resultMeta, nil
}

func (m *mockAuditClient) ListObjects(_ context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.fail["list:"+bucket]; err != nil {
		return s3.ListResult{}, err
	}
	var objects []s3.ObjectInfo
	for key := range m.objects {
		if len(key) <= len(bucket)+1 || key[:len(bucket)+1] != bucket+"/" {
			continue
		}
		objKey := key[len(bucket)+1:]
		if prefix != "" && !(len(objKey) >= len(prefix) && objKey[:len(prefix)] == prefix) {
			continue
		}
		objects = append(objects, s3.ObjectInfo{Key: objKey})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	result := s3.ListResult{Objects: objects, IsTruncated: false}
	return result, nil
}
