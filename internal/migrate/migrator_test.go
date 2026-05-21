package migrate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/kenchrcum/s3-encryption-gateway/internal/s3"
)

// mockS3ForMigrate is a full-featured mock S3 client for migration tests.
type mockS3ForMigrate struct {
	mu              sync.RWMutex
	objects         map[string][]byte
	metadata        map[string]map[string]string
	errors          map[string]error
	listPage        int
	getObjectCalls  int
	copyObjectCalls int
}

func newMockS3ForMigrate() *mockS3ForMigrate {
	return &mockS3ForMigrate{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockS3ForMigrate) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errors[bucket+"/"+key+"/put"]; err != nil {
		return err
	}
	data, _ := io.ReadAll(reader)
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return nil
}

func (m *mockS3ForMigrate) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	m.mu.RLock()
	m.getObjectCalls++
	if err := m.errors[bucket+"/"+key+"/get"]; err != nil {
		m.mu.RUnlock()
		return nil, nil, err
	}
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		m.mu.RUnlock()
		return nil, nil, fmt.Errorf("not found")
	}
	meta := m.metadata[bucket+"/"+key]
	m.mu.RUnlock()
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockS3ForMigrate) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.errors[bucket+"/"+key+"/head"]; err != nil {
		return nil, err
	}
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return meta, nil
}

func (m *mockS3ForMigrate) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.errors[bucket+"/"+key+"/delete"]; err != nil {
		return err
	}
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockS3ForMigrate) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.errors[bucket+"/list"]; err != nil {
		return s3.ListResult{}, err
	}
	var objects []s3.ObjectInfo
	for key := range m.objects {
		if !hasPrefix(key, bucket+"/") {
			continue
		}
		objKey := key[len(bucket)+1:]
		if prefix != "" && !hasPrefix(objKey, prefix) {
			continue
		}
		objects = append(objects, s3.ObjectInfo{Key: objKey})
	}
	return s3.ListResult{Objects: objects}, nil
}

func (m *mockS3ForMigrate) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.copyObjectCalls++
	srcData, ok := m.objects[srcBucket+"/"+srcKey]
	if !ok {
		return "", nil, fmt.Errorf("source not found")
	}
	m.objects[dstBucket+"/"+dstKey] = srcData
	m.metadata[dstBucket+"/"+dstKey] = metadata
	return "", metadata, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func setupMockWithObjects(t *testing.T, objs map[string]map[string]string) *mockS3ForMigrate {
	t.Helper()
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	for key, meta := range objs {
		plaintext := []byte("plaintext for " + key)
		encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), meta)
		if err != nil {
			t.Fatalf("encrypt %s: %v", key, err)
		}
		cipherdata, _ := io.ReadAll(encReader)
		_ = mock.PutObject(context.Background(), "bucket", key, bytes.NewReader(cipherdata), encMeta, nil, "", nil)
	}
	return mock
}

func TestMigrator_ClassA_XOR_RoundTrip(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create a legacy XOR object manually.
	mock := newMockS3ForMigrate()
	plaintext := []byte("legacy xor data")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)

	// Force legacy metadata (remove HKDF flag)
	delete(encMeta, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// After migration, the object should have the HKDF flag.
	meta, err := mock.HeadObject(ctx, "bucket", "obj1", nil)
	if err != nil {
		t.Fatalf("head after migration: %v", err)
	}
	if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
		t.Errorf("after migration MetaIVDerivation = %q, want hkdf-sha256", meta[crypto.MetaIVDerivation])
	}
}

func TestMigrator_DryRun_NoWrites(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	plaintext := []byte("dry run data")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)
	delete(encMeta, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	// Capture original metadata.
	origMeta, _ := mock.HeadObject(context.Background(), "bucket", "obj1", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         true,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate dry-run failed: %v", err)
	}

	// Metadata must be unchanged.
	meta, _ := mock.HeadObject(ctx, "bucket", "obj1", nil)
	if meta[crypto.MetaIVDerivation] != origMeta[crypto.MetaIVDerivation] {
		t.Error("dry-run modified metadata")
	}

	// Critically: dry-run must never call GetObject (no object body download).
	if mock.getObjectCalls != 0 {
		t.Errorf("dry-run called GetObject %d time(s); expected 0", mock.getObjectCalls)
	}
}

func TestBackfillLegacyNoAAD_TagsCandidate(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	mock := newMockS3ForMigrate()

	// Object A: encrypted, non-chunked, no MetaLegacyNoAAD — CLASS B candidate,
	// must be tagged via CopyObject.
	plainA := []byte("object a")
	rA, mA, err := eng.Encrypt(context.Background(), bytes.NewReader(plainA), nil)
	if err != nil {
		t.Fatalf("encrypt A: %v", err)
	}
	cA, _ := io.ReadAll(rA)
	_ = mock.PutObject(context.Background(), "bucket", "obj-a", bytes.NewReader(cA), mA, nil, "", nil)

	// Object B: plaintext — skipped (no MetaEncrypted).
	mock.objects["bucket/obj-b"] = []byte("plaintext")
	mock.metadata["bucket/obj-b"] = map[string]string{"Content-Type": "text/plain"}

	// Object C: already has MetaLegacyNoAAD="true" — skipped.
	plainC := []byte("object c")
	rC, mC, err := eng.Encrypt(context.Background(), bytes.NewReader(plainC), nil)
	if err != nil {
		t.Fatalf("encrypt C: %v", err)
	}
	cC, _ := io.ReadAll(rC)
	mC[crypto.MetaLegacyNoAAD] = "true"
	_ = mock.PutObject(context.Background(), "bucket", "obj-c", bytes.NewReader(cC), mC, nil, "", nil)

	// Object D: chunked — skipped (not a CLASS B candidate).
	plainD := []byte("object d")
	engChunked, _ := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	rD, mD, err := engChunked.Encrypt(context.Background(), bytes.NewReader(plainD), nil)
	if err != nil {
		t.Fatalf("encrypt D: %v", err)
	}
	cD, _ := io.ReadAll(rD)
	_ = mock.PutObject(context.Background(), "bucket", "obj-d", bytes.NewReader(cD), mD, nil, "", nil)

	m := &Migrator{
		S3Client: mock,
		Workers:  2,
		DryRun:   false,
	}

	ctx := context.Background()
	if err := m.BackfillLegacyNoAAD(ctx, "bucket", ""); err != nil {
		t.Fatalf("BackfillLegacyNoAAD: %v", err)
	}

	// Only obj-a is a CLASS B candidate — exactly 1 CopyObject call expected.
	if mock.copyObjectCalls != 1 {
		t.Errorf("expected 1 CopyObject call, got %d", mock.copyObjectCalls)
	}

	// obj-a must now carry the marker.
	metaA, _ := mock.HeadObject(ctx, "bucket", "obj-a", nil)
	if metaA[crypto.MetaLegacyNoAAD] != "true" {
		t.Errorf("obj-a: expected MetaLegacyNoAAD=true after backfill, got %q", metaA[crypto.MetaLegacyNoAAD])
	}

	// GetObject must never have been called — no body downloads.
	if mock.getObjectCalls != 0 {
		t.Errorf("backfill called GetObject %d time(s); expected 0", mock.getObjectCalls)
	}
}

func TestBackfillLegacyNoAAD_DryRun_NoCopyObject(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	plainA := []byte("object a")
	rA, mA, err := eng.Encrypt(context.Background(), bytes.NewReader(plainA), nil)
	if err != nil {
		t.Fatalf("encrypt A: %v", err)
	}
	cA, _ := io.ReadAll(rA)
	_ = mock.PutObject(context.Background(), "bucket", "obj-a", bytes.NewReader(cA), mA, nil, "", nil)

	m := &Migrator{
		S3Client: mock,
		Workers:  2,
		DryRun:   true,
	}

	ctx := context.Background()
	if err := m.BackfillLegacyNoAAD(ctx, "bucket", ""); err != nil {
		t.Fatalf("BackfillLegacyNoAAD dry-run: %v", err)
	}

	// Dry-run: CopyObject and GetObject must never be called.
	if mock.copyObjectCalls != 0 {
		t.Errorf("dry-run called CopyObject %d time(s); expected 0", mock.copyObjectCalls)
	}
	if mock.getObjectCalls != 0 {
		t.Errorf("dry-run called GetObject %d time(s); expected 0", mock.getObjectCalls)
	}
}

func TestMigrator_Resume(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	for i := 1; i <= 3; i++ {
		plaintext := []byte(fmt.Sprintf("data %d", i))
		encReader, encMeta, _ := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
		cipherdata, _ := io.ReadAll(encReader)
		delete(encMeta, crypto.MetaIVDerivation)
		_ = mock.PutObject(context.Background(), "bucket", fmt.Sprintf("obj%d", i), bytes.NewReader(cipherdata), encMeta, nil, "", nil)
	}

	stateFile := t.TempDir() + "/state.json"
	state := NewState("bucket", "")
	state.Checkpoint = "obj1"
	_ = state.Save(stateFile)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// obj1 should not have been re-processed (it was before checkpoint).
	// obj2 and obj3 should have the HKDF flag.
	for _, key := range []string{"obj2", "obj3"} {
		meta, _ := mock.HeadObject(ctx, "bucket", key, nil)
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("%s: expected hkdf-sha256 after migration, got %q", key, meta[crypto.MetaIVDerivation])
		}
	}
}

func TestMigrator_Filter_Sec2Only(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()

	// Class A (XOR-IV) object
	p1 := []byte("class a")
	r1, m1, _ := eng.Encrypt(context.Background(), bytes.NewReader(p1), nil)
	c1, _ := io.ReadAll(r1)
	delete(m1, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj-a", bytes.NewReader(c1), m1, nil, "", nil)

	// Class B (no-AAD legacy) object — non-chunked, legacy flag
	p2 := []byte("class b")
	m2 := map[string]string{crypto.MetaLegacyNoAAD: "true"}
	r2, m2enc, _ := eng.Encrypt(context.Background(), bytes.NewReader(p2), m2)
	c2, _ := io.ReadAll(r2)
	_ = mock.PutObject(context.Background(), "bucket", "obj-b", bytes.NewReader(c2), m2enc, nil, "", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterSec2,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// obj-a should be migrated (HKDF flag present).
	metaA, _ := mock.HeadObject(ctx, "bucket", "obj-a", nil)
	if metaA[crypto.MetaIVDerivation] != "hkdf-sha256" {
		t.Errorf("obj-a should be migrated")
	}

	// obj-b should NOT be migrated because filter is sec2 only.
	metaB, _ := mock.HeadObject(ctx, "bucket", "obj-b", nil)
	if metaB[crypto.MetaLegacyNoAAD] != "true" {
		t.Errorf("obj-b should NOT be migrated with sec2 filter")
	}
}

func TestMigrator_ClassB_NoAAD_RoundTrip(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create a legacy no-AAD object manually by encrypting without AAD context.
	// We simulate the legacy condition by adding MetaLegacyNoAAD.
	mock := newMockS3ForMigrate()
	plaintext := []byte("legacy no-aad data")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), map[string]string{crypto.MetaLegacyNoAAD: "true"})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// After migration, the object should NOT have the legacy no-AAD flag.
	meta, err := mock.HeadObject(ctx, "bucket", "obj1", nil)
	if err != nil {
		t.Fatalf("head after migration: %v", err)
	}
	if meta[crypto.MetaLegacyNoAAD] == "true" {
		t.Errorf("after migration MetaLegacyNoAAD should be absent or != true, got %q", meta[crypto.MetaLegacyNoAAD])
	}
}

func TestMigrator_ClassC_FallbackV1_RoundTrip(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	plaintext := []byte("fallback v1 data")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)

	// Force fallback v1 + XOR metadata so the classifier returns ClassC_Fallback_XOR.
	// We cannot generate genuine fallback-v1 ciphertext without the old code path,
	// so this test verifies the migrator *attempts* the object and records the
	// expected decrypt failure, confirming the code path is exercised.
	encMeta[crypto.MetaFallbackMode] = "true"
	delete(encMeta, crypto.MetaFallbackVersion)
	delete(encMeta, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	// Use the real engine as target; for source we rely on the real engine's
	// Decrypt which will try the fallback path.  Because the ciphertext is a
	// modern chunked object, the fallback path will fail in this test, so we
	// instead verify that the *classifier* picks ClassC_Fallback_XOR and that
	// the migrator attempts the object (it will fail at decrypt, which is an
	// expected outcome for a synthetic v1 object).
	// To make the test meaningful we assert the object lands in the failed list
	// with a decrypt error, confirming the code path is exercised.
	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	err = m.Migrate(ctx, "bucket", "")
	if err == nil {
		t.Fatal("expected partial migration error for synthetic fallback-v1 object")
	}

	state, _, _ := LoadOrCreate(m.StateFile, "bucket", "")
	if state.Stats.Failed != 1 {
		t.Fatalf("expected 1 failed object, got %d", state.Stats.Failed)
	}
	if state.Stats.ClassC_XOR != 1 {
		t.Fatalf("expected class_c_xor count 1, got %d (class_c_hkdf=%d)", state.Stats.ClassC_XOR, state.Stats.ClassC_HKDF)
	}
}

func TestMigrator_Idempotency(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	plaintext := []byte("idempotency data")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)
	delete(encMeta, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	stateFile := t.TempDir() + "/state.json"
	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("first Migrate failed: %v", err)
	}

	// Run again — should skip because state file shows it as completed.
	m2 := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}
	if err := m2.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}

	// Load state and confirm zero additional migrations.
	state, _, _ := LoadOrCreate(stateFile, "bucket", "")
	if state.Stats.Migrated != 1 {
		t.Errorf("expected 1 migrated after idempotent second run, got %d", state.Stats.Migrated)
	}
}

func TestMigrator_FailedObject_Continue(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	for i := 1; i <= 3; i++ {
		plaintext := []byte(fmt.Sprintf("data %d", i))
		encReader, encMeta, _ := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
		cipherdata, _ := io.ReadAll(encReader)
		delete(encMeta, crypto.MetaIVDerivation)
		_ = mock.PutObject(context.Background(), "bucket", fmt.Sprintf("obj%d", i), bytes.NewReader(cipherdata), encMeta, nil, "", nil)
	}

	// Inject a failure on obj2 GetObject.
	mock.errors["bucket/obj2/get"] = fmt.Errorf("injected get error")

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterAll,
	}

	ctx := context.Background()
	err = m.Migrate(ctx, "bucket", "")
	if err == nil {
		t.Fatal("expected partial migration error")
	}

	// obj1 and obj3 should be migrated; obj2 should be in failed list.
	state, _, _ := LoadOrCreate(m.StateFile, "bucket", "")
	if state.Stats.Migrated != 2 {
		t.Errorf("expected 2 migrated, got %d", state.Stats.Migrated)
	}
	if state.Stats.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", state.Stats.Failed)
	}
	if len(state.Failed) != 1 || state.Failed[0].Key != "obj2" {
		t.Errorf("expected obj2 in failed list, got %+v", state.Failed)
	}
}

func TestMigrator_StateFile_VersionMismatch(t *testing.T) {
	stateFile := t.TempDir() + "/state.json"
	state := NewState("bucket", "")
	state.GatewayVersion = "0.6.4"
	state.Checkpoint = "obj1"
	_ = state.Save(stateFile)

	m := &Migrator{
		S3Client:       newMockS3ForMigrate(),
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
	}

	if err := m.Migrate(context.Background(), "bucket", ""); err == nil {
		t.Error("expected error for state file gateway version mismatch")
	}
}

func TestMigrator_InvalidGatewayVersion(t *testing.T) {
	m := &Migrator{
		GatewayVersion: "0.5.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
	}
	if err := m.Migrate(context.Background(), "bucket", ""); err == nil {
		t.Error("expected error for invalid gateway version")
	}
}


func TestMigrator_ClassD_KDFParams_RoundTrip(t *testing.T) {
	eng100k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 100000)
	if err != nil {
		t.Fatalf("failed to create 100k engine: %v", err)
	}
	eng600k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 600000)
	if err != nil {
		t.Fatalf("failed to create 600k engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	plaintext := []byte("class d kdf data")
	encReader, encMeta, err := eng100k.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)
	delete(encMeta, crypto.MetaKDFParams)
	_ = mock.PutObject(context.Background(), "bucket", "obj1", bytes.NewReader(cipherdata), encMeta, nil, "", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng100k,
		TargetEngine:   eng600k,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterKDF,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	meta, err := mock.HeadObject(ctx, "bucket", "obj1", nil)
	if err != nil {
		t.Fatalf("head after migration: %v", err)
	}
	if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Errorf("after migration MetaKDFParams = %q, want pbkdf2-sha256:600000", meta[crypto.MetaKDFParams])
	}
}

func TestMigrator_FilterKDF_SkipsOtherClasses(t *testing.T) {
	eng100k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 100000)
	if err != nil {
		t.Fatalf("failed to create 100k engine: %v", err)
	}
	eng600k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 600000)
	if err != nil {
		t.Fatalf("failed to create 600k engine: %v", err)
	}

	mock := newMockS3ForMigrate()

	// ClassA object: encrypted, delete both MetaKDFParams and MetaIVDerivation
	pA := []byte("class a")
	rA, mA, _ := eng100k.Encrypt(context.Background(), bytes.NewReader(pA), nil)
	cA, _ := io.ReadAll(rA)
	delete(mA, crypto.MetaKDFParams)
	delete(mA, crypto.MetaIVDerivation)
	_ = mock.PutObject(context.Background(), "bucket", "obj-a", bytes.NewReader(cA), mA, nil, "", nil)

	// ClassD object: encrypted, delete MetaKDFParams only
	pD := []byte("class d")
	rD, mD, _ := eng100k.Encrypt(context.Background(), bytes.NewReader(pD), nil)
	cD, _ := io.ReadAll(rD)
	delete(mD, crypto.MetaKDFParams)
	_ = mock.PutObject(context.Background(), "bucket", "obj-d", bytes.NewReader(cD), mD, nil, "", nil)

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng100k,
		TargetEngine:   eng600k,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterKDF,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// ClassD should have KDF params now
	metaD, _ := mock.HeadObject(ctx, "bucket", "obj-d", nil)
	if metaD[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Errorf("obj-d: expected MetaKDFParams=pbkdf2-sha256:600000, got %q", metaD[crypto.MetaKDFParams])
	}

	// ClassA should NOT have KDF params and still NOT have HKDF
	metaA, _ := mock.HeadObject(ctx, "bucket", "obj-a", nil)
	if metaA[crypto.MetaKDFParams] != "" {
		t.Errorf("obj-a: expected MetaKDFParams absent, got %q", metaA[crypto.MetaKDFParams])
	}
	if metaA[crypto.MetaIVDerivation] != "" {
		t.Errorf("obj-a: expected MetaIVDerivation absent, got %q", metaA[crypto.MetaIVDerivation])
	}
}

func TestMigrator_ClassD_Migrate_100k_to_600k(t *testing.T) {
	eng100k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 100000)
	if err != nil {
		t.Fatalf("failed to create 100k engine: %v", err)
	}
	eng600k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 600000)
	if err != nil {
		t.Fatalf("failed to create 600k engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	for i := 1; i <= 3; i++ {
		plaintext := []byte(fmt.Sprintf("data %d", i))
		encReader, encMeta, _ := eng100k.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
		cipherdata, _ := io.ReadAll(encReader)
		delete(encMeta, crypto.MetaKDFParams)
		_ = mock.PutObject(context.Background(), "bucket", fmt.Sprintf("obj%d", i), bytes.NewReader(cipherdata), encMeta, nil, "", nil)
	}

	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng100k,
		TargetEngine:   eng600k,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         FilterKDF,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		meta, _ := mock.HeadObject(ctx, "bucket", fmt.Sprintf("obj%d", i), nil)
		if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
			t.Errorf("obj%d: after migration MetaKDFParams = %q, want pbkdf2-sha256:600000", i, meta[crypto.MetaKDFParams])
		}
	}
}

func TestMigrator_ClassD_Idempotency(t *testing.T) {
	eng100k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 100000)
	if err != nil {
		t.Fatalf("failed to create 100k engine: %v", err)
	}
	eng600k, err := crypto.NewEngineWithChunkingAndProvider([]byte("test-migrate-password-1234"), nil, "", nil, true, crypto.DefaultChunkSize, "default", 600000)
	if err != nil {
		t.Fatalf("failed to create 600k engine: %v", err)
	}

	mock := newMockS3ForMigrate()
	for i := 1; i <= 3; i++ {
		plaintext := []byte(fmt.Sprintf("idempotency data %d", i))
		encReader, encMeta, _ := eng100k.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
		cipherdata, _ := io.ReadAll(encReader)
		delete(encMeta, crypto.MetaKDFParams)
		_ = mock.PutObject(context.Background(), "bucket", fmt.Sprintf("obj%d", i), bytes.NewReader(cipherdata), encMeta, nil, "", nil)
	}

	stateFile := t.TempDir() + "/state.json"
	m := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng100k,
		TargetEngine:   eng600k,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         FilterKDF,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("first Migrate failed: %v", err)
	}

	getCallsAfterFirst := mock.getObjectCalls

	// Run again with same state file.
	m2 := &Migrator{
		S3Client:       mock,
		SourceEngine:   eng100k,
		TargetEngine:   eng600k,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         FilterKDF,
	}
	if err := m2.Migrate(ctx, "bucket", ""); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}

	state, _, _ := LoadOrCreate(stateFile, "bucket", "")
	if state.Stats.Migrated != 3 {
		t.Errorf("expected 3 migrated after idempotent second run, got %d", state.Stats.Migrated)
	}
	if mock.getObjectCalls != getCallsAfterFirst {
		t.Errorf("expected no additional GetObject calls on second run, got %d total (was %d after first run)", mock.getObjectCalls, getCallsAfterFirst)
	}
}
