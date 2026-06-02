//go:build conformance

// Package conformance is the tier-2 multi-provider test suite.
//
// Build tag: conformance (never runs under default `go test ./...`).
//
// These tests verify the s3eg-migrate offline migration tool against every
// registered provider. Objects are written directly to the S3 backend,
// the migration tool is run, and results are verified via HeadObject and
// GetObject.
package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/migrate"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testPassword is the deterministic test password used for all engines.
var testPassword = []byte("test-migration-password-12345678")

// newS3Client creates an internal/s3 client from a provider instance.
func newS3Client(t *testing.T, inst provider.Instance) s3.Client {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     inst.ProviderName,
		UseSSL:       false,
		UsePathStyle: true,
	}
	client, err := s3.NewClient(cfg)
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	return client
}

// newEngine creates a chunked encryption engine for migration tests.
func newEngine(t *testing.T) crypto.EncryptionEngine {
	t.Helper()
	eng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	return eng
}

// putEncryptedObject encrypts plaintext and stores it in the bucket with the
// given key, optionally mutating the metadata before storage.
func putEncryptedObject(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string, plaintext []byte, metaMutate func(map[string]string)) {
	t.Helper()
	ctx := context.Background()

	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt %s: %v", key, err)
	}
	cipherdata, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted %s: %v", key, err)
	}

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	if err := client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata), encMeta, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// putEncryptedObjectWithMeta encrypts plaintext with the given metadata and
// stores it in the bucket, optionally mutating the metadata before storage.
func putEncryptedObjectWithMeta(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string, plaintext []byte, encryptMeta map[string]string, metaMutate func(map[string]string)) {
	t.Helper()
	ctx := context.Background()

	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), encryptMeta)
	if err != nil {
		t.Fatalf("encrypt %s: %v", key, err)
	}
	cipherdata, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted %s: %v", key, err)
	}

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	if err := client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata), encMeta, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// headMeta reads object metadata via HeadObject.
func headMeta(t *testing.T, client s3.Client, bucket, key string) map[string]string {
	t.Helper()
	ctx := context.Background()
	meta, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		t.Fatalf("head object %s: %v", key, err)
	}
	return meta
}

// decryptObject reads and decrypts an object, returning the plaintext bytes.
func decryptObject(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string) []byte {
	t.Helper()
	ctx := context.Background()
	reader, meta, err := client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		t.Fatalf("get object %s: %v", key, err)
	}
	defer reader.Close()

	decReader, _, err := eng.Decrypt(context.Background(), reader, meta)
	if err != nil {
		t.Fatalf("decrypt %s: %v", key, err)
	}
	plaintext, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("read decrypted %s: %v", key, err)
	}
	return plaintext
}

// testMaint1_SEC2_XOR_to_HKDF verifies that legacy XOR-IV chunked objects are
// re-encrypted with HKDF derivation and remain decryptable.
func testMaint1_SEC2_XOR_to_HKDF(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/sec2/%s/", suf)

	wantPlain := []byte("hello sec2 migration world")
	keys := make([]string, 5)
	for i := 0; i < 5; i++ {
		keys[i] = fmt.Sprintf("%sobj-%02d", prefix, i)
		putEncryptedObject(t, client, eng, bucket, keys[i], wantPlain, func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterSec2,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	for _, key := range keys {
		meta := headMeta(t, client, bucket, key)
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("%s: expected MetaIVDerivation=hkdf-sha256, got %q", key, meta[crypto.MetaIVDerivation])
		}
		got := decryptObject(t, client, eng, bucket, key)
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("%s: plaintext mismatch after migration", key)
		}
	}
}

// testMaint1_Mixed_AllClasses writes objects simulating multiple legacy
// classes and migrates them all in one pass.
func testMaint1_Mixed_AllClasses(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/mixed/%s/", suf)

	wantPlain := []byte("mixed migration plaintext")

	for i := 0; i < 3; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("%sa-%d", prefix, i), wantPlain, func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	for i := 0; i < 2; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("%smodern-%d", prefix, i), wantPlain, nil)
	}

	plainEng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("failed to create plain engine: %v", err)
	}
	for i := 0; i < 3; i++ {
		putEncryptedObjectWithMeta(t, client, plainEng, bucket, fmt.Sprintf("%sb-%d", prefix, i), wantPlain,
			map[string]string{"Content-Type": "application/octet-stream"},
			func(meta map[string]string) {
				meta[crypto.MetaLegacyNoAAD] = "true"
			})
	}

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("%sa-%d", prefix, i))
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("mixed/a-%d: expected hkdf-sha256, got %q", i, meta[crypto.MetaIVDerivation])
		}
	}

	for i := 0; i < 3; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("%sb-%d", prefix, i))
		if meta[crypto.MetaLegacyNoAAD] == "true" {
			t.Errorf("mixed/b-%d: MetaLegacyNoAAD should be absent after migration", i)
		}
	}

	for i := 0; i < 2; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("%smodern-%d", prefix, i))
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("mixed/modern-%d: expected unchanged hkdf-sha256, got %q", i, meta[crypto.MetaIVDerivation])
		}
		got := decryptObject(t, client, eng, bucket, fmt.Sprintf("%smodern-%d", prefix, i))
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("mixed/modern-%d: plaintext changed unexpectedly", i)
		}
	}
}

// testMaint1_DryRun_ReportsCorrectly verifies that dry-run mode classifies
// objects correctly and makes no writes.
func testMaint1_DryRun_ReportsCorrectly(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/dryrun/%s/", suf)

	putEncryptedObject(t, client, eng, bucket, prefix+"modern", []byte("modern"), nil)
	putEncryptedObject(t, client, eng, bucket, prefix+"xor1", []byte("xor"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, prefix+"xor2", []byte("xor"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	report, err := migrate.DryRunScan(context.Background(), client, bucket, prefix, nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}

	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.Modern != 1 {
		t.Errorf("Modern = %d, want 1", report.Modern)
	}
	if report.ClassA != 2 {
		t.Errorf("ClassA = %d, want 2", report.ClassA)
	}

	meta := headMeta(t, client, bucket, prefix+"xor1")
	if meta[crypto.MetaIVDerivation] != "" {
		t.Errorf("dry-run should not have mutated metadata")
	}
}

// testMaint1_Idempotency_E2E runs a full migration twice and confirms the
// second run skips everything.
func testMaint1_Idempotency_E2E(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/idemp/%s/", suf)

	for i := 0; i < 5; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("%sobj-%d", prefix, i), []byte("data"), func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	stateFile := t.TempDir() + "/state.json"
	m1 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m1.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("first Migrate failed: %v", err)
	}

	m2 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}
	if err := m2.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}

	state, _, _ := migrate.LoadOrCreate(stateFile, bucket, prefix)
	if state.Stats.Migrated != 5 {
		t.Errorf("first run migrated = %d, want 5; second run should have 0 new", state.Stats.Migrated)
	}
	if state.Stats.Skipped != 5 {
		t.Errorf("second run skipped = %d, want 5", state.Stats.Skipped)
	}
}

// testMaint1_Resume_E2E verifies that a migration can be resumed from a state
// file after an interruption.
func testMaint1_Resume_E2E(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/resume/%s/", suf)

	for i := 0; i < 5; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("%sobj-%02d", prefix, i), []byte("data"), func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	stateFile := t.TempDir() + "/state.json"
	state := migrate.NewState(bucket, prefix)
	state.Checkpoint = fmt.Sprintf("%sobj-01", prefix)
	state.GatewayVersion = "0.7.0"
	state.Stats.Migrated = 2
	if err := state.Save(stateFile); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	finalState, _, err := migrate.LoadOrCreate(stateFile, bucket, prefix)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if finalState.Stats.Migrated != 5 {
		t.Errorf("total migrated = %d, want 5 (2 pre-seeded + 3 resumed)", finalState.Stats.Migrated)
	}
}

// testMaint1_GatewayVersion_Invalid verifies that an unsupported gateway
// version causes the tool to fail immediately without making any writes.
func testMaint1_GatewayVersion_Invalid(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/badver/%s/", suf)

	putEncryptedObject(t, client, eng, bucket, prefix+"obj", []byte("data"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.5.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err == nil {
		t.Fatal("expected error for invalid gateway version")
	}

	meta := headMeta(t, client, bucket, prefix+"obj")
	if meta[crypto.MetaIVDerivation] != "" {
		t.Errorf("object should not have been migrated with invalid gateway version")
	}
}

// testMaint1_StateFile_VersionMismatch verifies that resuming with a different
// gateway version is rejected.
func testMaint1_StateFile_VersionMismatch(t *testing.T, inst provider.Instance) {
	t.Helper()
	stateFile := t.TempDir() + "/state.json"
	state := migrate.NewState(inst.Bucket, "maint1/vs/")
	state.GatewayVersion = "0.6.4"
	state.Checkpoint = "obj-01"
	if err := state.Save(stateFile); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	client := newS3Client(t, inst)
	eng := newEngine(t)

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
	}

	if err := m.Migrate(context.Background(), inst.Bucket, "maint1/vs/"); err == nil {
		t.Fatal("expected error for state file gateway version mismatch")
	}
}

// testMaint1_GoldenPath_AllBreakingChanges is the conformance-phase golden-path
// test for V1.0-MAINT-1. It creates objects combining every legacy breaking
// change (SEC-2, SEC-4, SEC-27), runs the migration tool, and asserts that
// every object is migrated to ClassModern and remains fully readable.
func testMaint1_GoldenPath_AllBreakingChanges(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/golden/%s/", suf)

	wantPlain := []byte("golden-path-plaintext combining sec2 sec4 sec27")

	putEncryptedObject(t, client, eng, bucket, prefix+"a-1", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, prefix+"a-2", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	plainEng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("failed to create plain engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, plainEng, bucket, prefix+"b-1", wantPlain,
		map[string]string{"Content-Type": "application/octet-stream"},
		func(meta map[string]string) {
			meta[crypto.MetaLegacyNoAAD] = "true"
		})

	fallbackEng, err := crypto.NewTestEngineWithFallbackProfile(testPassword, false)
	if err != nil {
		t.Fatalf("failed to create fallback engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, fallbackEng, bucket, prefix+"c-1", wantPlain,
		map[string]string{
			"Content-Type":       "application/octet-stream",
			"x-amz-meta-project": "s3-encryption-gateway",
		},
		nil)
	putEncryptedObjectWithMeta(t, client, fallbackEng, bucket, prefix+"c-2", wantPlain,
		map[string]string{
			"Content-Type":       "application/octet-stream",
			"x-amz-meta-project": "s3-encryption-gateway",
		},
		func(meta map[string]string) {
			meta[crypto.MetaLegacyNoAAD] = "true"
		})

	putEncryptedObject(t, client, eng, bucket, prefix+"modern-1", wantPlain, nil)
	putEncryptedObject(t, client, eng, bucket, prefix+"modern-2", wantPlain, nil)

	ctx := context.Background()
	if err := client.PutObject(ctx, bucket, prefix+"plain.txt", bytes.NewReader(wantPlain),
		map[string]string{"Content-Type": "text/plain"}, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put plaintext: %v", err)
	}

	report, err := migrate.DryRunScan(ctx, client, bucket, prefix, nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}
	if report.Total != 8 {
		t.Errorf("DryRun Total = %d, want 8", report.Total)
	}
	if report.Modern != 2 {
		t.Errorf("DryRun Modern = %d, want 2", report.Modern)
	}
	if report.ClassA != 2 {
		t.Errorf("DryRun ClassA = %d, want 2", report.ClassA)
	}
	if report.ClassB != 1 {
		t.Errorf("DryRun ClassB = %d, want 1", report.ClassB)
	}
	if report.ClassC_XOR != 2 {
		t.Errorf("DryRun ClassC_XOR = %d, want 2", report.ClassC_XOR)
	}
	if report.Plaintext != 1 {
		t.Errorf("DryRun Plaintext = %d, want 1", report.Plaintext)
	}

	stateFile := t.TempDir() + "/golden-state.json"
	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         true,
		VerifyDelay:    100 * time.Millisecond,
		Filter:         migrate.FilterAll,
	}
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	keys := []string{
		prefix + "a-1", prefix + "a-2",
		prefix + "b-1",
		prefix + "c-1", prefix + "c-2",
		prefix + "modern-1", prefix + "modern-2",
		prefix + "plain.txt",
	}
	for _, key := range keys {
		meta := headMeta(t, client, bucket, key)
		class := migrate.ClassifyObject(meta)
		if class != migrate.ClassModern && class != migrate.ClassPlaintext {
			t.Errorf("%s: expected ClassModern or ClassPlaintext after migration, got %s", key, migrate.ClassToString(class))
		}
		if class == migrate.ClassPlaintext {
			continue
		}
		got := decryptObject(t, client, eng, bucket, key)
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("%s: plaintext mismatch after migration", key)
		}
	}

	for _, key := range []string{prefix + "a-1", prefix + "a-2"} {
		meta := headMeta(t, client, bucket, key)
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("%s: expected MetaIVDerivation=hkdf-sha256, got %q", key, meta[crypto.MetaIVDerivation])
		}
	}
	metaB := headMeta(t, client, bucket, prefix+"b-1")
	if metaB[crypto.MetaLegacyNoAAD] == "true" {
		t.Errorf("golden/b-1: MetaLegacyNoAAD should be absent after migration")
	}
	for _, key := range []string{prefix + "c-1", prefix + "c-2"} {
		meta := headMeta(t, client, bucket, key)
		if meta[crypto.MetaFallbackMode] == "true" && meta[crypto.MetaFallbackVersion] != "2" {
			t.Errorf("%s: fallback object must have version '2' after migration, got %q", key, meta[crypto.MetaFallbackVersion])
		}
	}

	m2 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}
	if err := m2.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}
	state, _, err := migrate.LoadOrCreate(stateFile, bucket, prefix)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	wantMigrated := int64(5)
	if state.Stats.Migrated != wantMigrated {
		t.Errorf("total migrated = %d, want %d (should not increase on second run)", state.Stats.Migrated, wantMigrated)
	}
	wantSkipped := int64(11)
	if state.Stats.Skipped != wantSkipped {
		t.Errorf("total skipped = %d, want %d", state.Stats.Skipped, wantSkipped)
	}
}

// testMaint1_DryRun_Scan confirms the classification and reporting logic
// works end-to-end against a real backend.
func testMaint1_DryRun_Scan(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/dryscan/%s/", suf)

	putEncryptedObject(t, client, eng, bucket, prefix+"modern", []byte("modern"), nil)
	putEncryptedObject(t, client, eng, bucket, prefix+"legacy1", []byte("legacy"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, prefix+"plain.txt", []byte("plaintext"), func(meta map[string]string) {
		delete(meta, crypto.MetaEncrypted)
		delete(meta, "x-amz-meta-e")
	})

	report, err := migrate.DryRunScan(context.Background(), client, bucket, prefix, nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}
	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.Modern != 1 {
		t.Errorf("Modern = %d, want 1", report.Modern)
	}
	if report.ClassA != 1 {
		t.Errorf("ClassA = %d, want 1", report.ClassA)
	}
	if report.Plaintext != 1 {
		t.Errorf("Plaintext = %d, want 1", report.Plaintext)
	}
	if len(report.Samples["class_a_xor"]) != 1 {
		t.Errorf("expected 1 sample for class_a_xor, got %d", len(report.Samples["class_a_xor"]))
	}
}

// testMaint1_VerifyAfterWrite detects a 1-byte corruption after PutObject.
func testMaint1_VerifyAfterWrite(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket
	suf := uniqueSuffix(t)
	prefix := fmt.Sprintf("maint1/verify/%s/", suf)

	wantPlain := []byte("verify me please")
	putEncryptedObject(t, client, eng, bucket, prefix+"obj", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         true,
		VerifyDelay:    100 * time.Millisecond,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate with verify failed: %v", err)
	}

	meta := headMeta(t, client, bucket, prefix+"obj")
	if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
		t.Errorf("expected hkdf-sha256 after migration, got %q", meta[crypto.MetaIVDerivation])
	}
}

// ------------------------------------------------------------------
// V1.0-MGMT-2 KDF iteration migration conformance tests
// ------------------------------------------------------------------

// mgmt2Password matches the default harness password so gateway round-trips
// and direct-backend objects use the same key material.
var mgmt2Password = kdfTestPassword

// testMGMT2_KDF_DryRun_DetectsClassD writes 3 ClassD objects (no MetaKDFParams)
// and 2 modern objects, then runs DryRunScan and asserts the report counts.
func testMGMT2_KDF_DryRun_DetectsClassD(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng100k := newEngine100k(t)
	bucket := inst.Bucket
	prefix := fmt.Sprintf("mgmt2/dryrun/%s/", uniqueSuffix(t))

	for i := 0; i < 3; i++ {
		putEncryptedObject(t, client, eng100k, bucket, fmt.Sprintf("%sclassd-%d", prefix, i), []byte("classd"), func(meta map[string]string) {
			delete(meta, crypto.MetaKDFParams)
		})
	}
	for i := 0; i < 2; i++ {
		putEncryptedObject(t, client, eng100k, bucket, fmt.Sprintf("%smodern-%d", prefix, i), []byte("modern"), nil)
	}

	report, err := migrate.DryRunScan(context.Background(), client, bucket, prefix, nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}
	if report.ClassD != 3 {
		t.Errorf("ClassD = %d, want 3", report.ClassD)
	}
	if report.Modern != 2 {
		t.Errorf("Modern = %d, want 2", report.Modern)
	}
}

// testMGMT2_KDF_Migrate_100k_to_600k writes 5 ClassD objects, runs the
// migrator with FilterKDF, and asserts that every object now carries
// MetaKDFParams == "pbkdf2-sha256:600000".
func testMGMT2_KDF_Migrate_100k_to_600k(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng100k := newEngine100k(t)
	bucket := inst.Bucket
	prefix := fmt.Sprintf("mgmt2/migrate/%s/", uniqueSuffix(t))

	for i := 0; i < 5; i++ {
		putEncryptedObject(t, client, eng100k, bucket, fmt.Sprintf("%sobj-%d", prefix, i), []byte("migrate-me"), func(meta map[string]string) {
			delete(meta, crypto.MetaKDFParams)
		})
	}

	m := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          2,
		StateFile:        t.TempDir() + "/state.json",
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterKDF,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("%sobj-%d", prefix, i))
		if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
			t.Errorf("obj-%d: MetaKDFParams = %q, want %q", i, meta[crypto.MetaKDFParams], "pbkdf2-sha256:600000")
		}
	}
}

// testMGMT2_KDF_Idempotency runs a ClassD migration twice and asserts that
// the second pass skips every object.
func testMGMT2_KDF_Idempotency(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng100k := newEngine100k(t)
	bucket := inst.Bucket
	prefix := fmt.Sprintf("mgmt2/idemp/%s/", uniqueSuffix(t))

	for i := 0; i < 3; i++ {
		putEncryptedObject(t, client, eng100k, bucket, fmt.Sprintf("%sobj-%d", prefix, i), []byte("idemp"), func(meta map[string]string) {
			delete(meta, crypto.MetaKDFParams)
		})
	}

	stateFile := t.TempDir() + "/state.json"
	m1 := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          2,
		StateFile:        stateFile,
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterKDF,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}

	ctx := context.Background()
	if err := m1.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("first Migrate failed: %v", err)
	}

	m2 := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          2,
		StateFile:        stateFile,
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterKDF,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}
	if err := m2.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}

	state, _, err := migrate.LoadOrCreate(stateFile, bucket, prefix)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.Stats.Migrated != 3 {
		t.Errorf("first run migrated = %d, want 3", state.Stats.Migrated)
	}
	if state.Stats.Skipped != 3 {
		t.Errorf("second run skipped = %d, want 3", state.Stats.Skipped)
	}
}

// testMGMT2_KDF_FilterKDF_SkipsOtherClasses writes 2 ClassA and 2 ClassD
// objects, runs the migrator with FilterKDF, and asserts that only ClassD
// objects are re-encrypted.
func testMGMT2_KDF_FilterKDF_SkipsOtherClasses(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng600k, err := crypto.NewEngineWithOpts(mgmt2Password, nil, crypto.WithChunking(true))
	if err != nil {
		t.Fatalf("newEngine600k: %v", err)
	}
	bucket := inst.Bucket
	prefix := fmt.Sprintf("mgmt2/filter/%s/", uniqueSuffix(t))

	// Capture ClassA metadata before migration to detect any unwanted changes.
	classAPreMigrate := make([]map[string]string, 2)
	for i := 0; i < 2; i++ {
		putEncryptedObject(t, client, eng600k, bucket, fmt.Sprintf("%sclassa-%d", prefix, i), []byte("classa"), func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
		classAPreMigrate[i] = headMeta(t, client, bucket, fmt.Sprintf("%sclassa-%d", prefix, i))
	}

	eng100k := newEngine100k(t)
	for i := 0; i < 2; i++ {
		putEncryptedObject(t, client, eng100k, bucket, fmt.Sprintf("%sclassd-%d", prefix, i), []byte("classd"), func(meta map[string]string) {
			delete(meta, crypto.MetaKDFParams)
		})
	}

	m := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          2,
		StateFile:        t.TempDir() + "/state.json",
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterKDF,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// ClassA objects must be untouched: their metadata must be identical to
	// what was recorded before the migration run.
	for i := 0; i < 2; i++ {
		metaAfter := headMeta(t, client, bucket, fmt.Sprintf("%sclassa-%d", prefix, i))
		pre := classAPreMigrate[i]
		if metaAfter[crypto.MetaKDFParams] != pre[crypto.MetaKDFParams] {
			t.Errorf("classa-%d: should not have been migrated, MetaKDFParams changed from %q to %q",
				i, pre[crypto.MetaKDFParams], metaAfter[crypto.MetaKDFParams])
		}
		if metaAfter[crypto.MetaIV] != pre[crypto.MetaIV] {
			t.Errorf("classa-%d: should not have been migrated, MetaIV changed", i)
		}
	}
	for i := 0; i < 2; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("%sclassd-%d", prefix, i))
		if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
			t.Errorf("classd-%d: should have been migrated, got MetaKDFParams=%q", i, meta[crypto.MetaKDFParams])
		}
	}
}

// testMGMT2_KDF_Mixed_AllClasses writes one object of every class and a
// plaintext object, then runs the migrator with FilterAll and asserts that
// every legacy class is promoted to ClassModern.
func testMGMT2_KDF_Mixed_AllClasses(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	bucket := inst.Bucket
	prefix := fmt.Sprintf("mgmt2/mixed/%s/", uniqueSuffix(t))

	// ClassA (XOR IV derivation)
	eng600k, err := crypto.NewEngineWithOpts(mgmt2Password, nil, crypto.WithChunking(true))
	if err != nil {
		t.Fatalf("newEngine600k: %v", err)
	}
	putEncryptedObject(t, client, eng600k, bucket, prefix+"classa-0", []byte("mixed"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	// ClassB (no AAD legacy)
	plainEng, err := crypto.NewEngineWithOpts(mgmt2Password, nil, crypto.WithChunking(false))
	if err != nil {
		t.Fatalf("new plain engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, plainEng, bucket, prefix+"classb-0", []byte("mixed"),
		map[string]string{"Content-Type": "application/octet-stream"},
		func(meta map[string]string) {
			meta[crypto.MetaLegacyNoAAD] = "true"
		})

	// ClassC (fallback mode)
	fallbackEng, err := crypto.NewTestEngineWithFallbackProfile(mgmt2Password, false)
	if err != nil {
		t.Fatalf("new fallback engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, fallbackEng, bucket, prefix+"classc-0", []byte("mixed"),
		map[string]string{"Content-Type": "application/octet-stream"},
		nil)

	// ClassD (legacy KDF)
	eng100k := newEngine100k(t)
	putEncryptedObject(t, client, eng100k, bucket, prefix+"classd-0", []byte("mixed"), func(meta map[string]string) {
		delete(meta, crypto.MetaKDFParams)
	})

	// ClassModern (already modern)
	putEncryptedObject(t, client, eng600k, bucket, prefix+"modern-0", []byte("mixed"), nil)

	// Plaintext
	ctx := context.Background()
	if err := client.PutObject(ctx, bucket, prefix+"plain.txt", bytes.NewReader([]byte("mixed")),
		map[string]string{"Content-Type": "text/plain"}, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put plaintext: %v", err)
	}

	m := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          2,
		StateFile:        t.TempDir() + "/state.json",
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterAll,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}
	if err := m.Migrate(ctx, bucket, prefix); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	keys := []string{
		prefix + "classa-0",
		prefix + "classb-0",
		prefix + "classc-0",
		prefix + "classd-0",
		prefix + "modern-0",
		prefix + "plain.txt",
	}
	for _, key := range keys {
		meta := headMeta(t, client, bucket, key)
		class := migrate.ClassifyObject(meta)
		if class != migrate.ClassModern && class != migrate.ClassPlaintext {
			t.Errorf("%s: expected ClassModern or ClassPlaintext after migration, got %s", key, migrate.ClassToString(class))
		}
	}
}

// testMGMT2_KDF_GoldenPath is the end-to-end headline test for V1.0-MGMT-2.
// It writes via a 100k gateway, verifies metadata, migrates with FilterKDF,
// and asserts that the object is still readable after migration.
func testMGMT2_KDF_GoldenPath(t *testing.T, inst provider.Instance) {
	t.Helper()
	bucket := inst.Bucket
	key := uniqueKey(t)
	plaintext := []byte("golden-path-plaintext")

	// 1. Write via 100k gateway.
	gw100k := harness.StartGateway(t, inst, harness.WithPBKDF2Iterations(100000))
	put(t, gw100k, bucket, key, plaintext)

	// 2. Verify MetaKDFParams directly on backend.
	client := newS3Client(t, inst)
	meta := headMeta(t, client, bucket, key)
	if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:100000" {
		t.Fatalf("pre-migrate MetaKDFParams = %q, want pbkdf2-sha256:100000", meta[crypto.MetaKDFParams])
	}

	// 3. Start 600k gateway and GET (metadata-driven decryption).
	gw600k := harness.StartGateway(t, inst)
	got := get(t, gw600k, bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("pre-migrate GET mismatch")
	}

	// 4. Run migration with FilterKDF.
	m := &migrate.Migrator{
		S3Client:         client,
		Password:         mgmt2Password,
		GatewayVersion:   "0.7.0",
		Workers:          1,
		StateFile:        t.TempDir() + "/state.json",
		DryRun:           false,
		Verify:           false,
		Filter:           migrate.FilterKDF,
		SourceIterations: 100000,
		TargetIterations: 600000,
	}
	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, key); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// 5. Verify MetaKDFParams updated.
	meta = headMeta(t, client, bucket, key)
	if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Fatalf("post-migrate MetaKDFParams = %q, want pbkdf2-sha256:600000", meta[crypto.MetaKDFParams])
	}

	// 6. GET still works via 600k gateway.
	got = get(t, gw600k, bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("post-migrate GET mismatch")
	}
}
