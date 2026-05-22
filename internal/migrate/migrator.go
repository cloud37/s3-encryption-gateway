package migrate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// S3Client is the minimal S3 interface needed by the migration tool.
type S3Client interface {
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput) error
	GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
	DeleteObject(ctx context.Context, bucket, key string, versionID *string) error
	ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error)
	CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error)
}

// MigrationClassFilter controls which object classes are processed.
type MigrationClassFilter string

const (
	FilterAll   MigrationClassFilter = "all"
	FilterSec2  MigrationClassFilter = "sec2"
	FilterSec4  MigrationClassFilter = "sec4"
	FilterSec27 MigrationClassFilter = "sec27"
	FilterKDF   MigrationClassFilter = "kdf"
)

// IsAllowed reports whether the given object class passes the filter.
func (f MigrationClassFilter) IsAllowed(c ObjectClass) bool {
	switch f {
	case FilterAll, "":
		return true
	case FilterSec2:
		return c == ClassA_XOR
	case FilterSec4:
		return c == ClassB_NoAAD
	case FilterSec27:
		return c == ClassC_Fallback_XOR || c == ClassC_Fallback_HKDF
	case FilterKDF:
		return c == ClassD_LegacyKDF
	default:
		return true
	}
}

// Migrator orchestrates the re-encryption of objects in an S3 bucket.
type Migrator struct {
	S3Client         S3Client
	SourceEngine     crypto.EncryptionEngine
	TargetEngine     crypto.EncryptionEngine
	GatewayVersion   string // e.g. "0.6.4" or "0.7.0"
	Workers          int
	StateFile        string
	DryRun           bool
	Verify           bool
	VerifyDelay      time.Duration
	Filter           MigrationClassFilter
	Logger           *slog.Logger
	Password         []byte // password for auto-constructing engines from iteration counts
	SourceIterations int    // PBKDF2 iterations of existing objects (default 100000)
	TargetIterations int    // PBKDF2 iterations for re-encrypted objects (default 600000)
}

// Migrate iterates over objects in the given bucket and prefix, classifying
// and migrating each one according to the configured filter.
func (m *Migrator) Migrate(ctx context.Context, bucket, prefix string) error {
	if err := m.validateGatewayVersion(); err != nil {
		return err
	}

	state, loaded, err := LoadOrCreate(m.StateFile, bucket, prefix)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	if loaded {
		if state.GatewayVersion != "" && state.GatewayVersion != m.GatewayVersion {
			return fmt.Errorf("state file gateway version mismatch: state has %q, current run requests %q. Start a fresh run with a new --state-file", state.GatewayVersion, m.GatewayVersion)
		}
		if state.DryRun != m.DryRun {
			return fmt.Errorf("state file dry-run mismatch: state has dry_run=%v, current run requests dry_run=%v. Use a different --state-file", state.DryRun, m.DryRun)
		}
	}
	state.GatewayVersion = m.GatewayVersion
	state.DryRun = m.DryRun

	// Auto-construct engines from iteration counts when caller did not
	// supply them explicitly.
	if m.SourceEngine == nil && m.SourceIterations > 0 {
		if len(m.Password) == 0 {
			return fmt.Errorf("SourceEngine is nil and SourceIterations is set, but Password is empty")
		}
		m.SourceEngine, err = crypto.NewEngineWithOpts(m.Password, nil,
			crypto.WithPBKDF2Iterations(m.SourceIterations))
		if err != nil {
			return fmt.Errorf("failed to build source engine: %w", err)
		}
	}
	if m.TargetEngine == nil && m.TargetIterations > 0 {
		if len(m.Password) == 0 {
			return fmt.Errorf("TargetEngine is nil and TargetIterations is set, but Password is empty")
		}
		m.TargetEngine, err = crypto.NewEngineWithOpts(m.Password, nil,
			crypto.WithPBKDF2Iterations(m.TargetIterations))
		if err != nil {
			return fmt.Errorf("failed to build target engine: %w", err)
		}
	}

	if m.Logger == nil {
		m.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	m.Logger.Info("migration starting",
		"bucket", bucket,
		"prefix", prefix,
		"gateway_version", m.GatewayVersion,
		"workers", m.Workers,
		"dry_run", m.DryRun,
		"filter", string(m.Filter),
		"checkpoint", state.Checkpoint,
	)

	// Probe S3 endpoint.
	if err := m.probeS3(ctx, bucket); err != nil {
		return err
	}

	workers := m.Workers
	if workers <= 0 {
		workers = 4
	}

	var (
		wg      sync.WaitGroup
		jobs    = make(chan migrateJob, workers*2)
		doneCh  = make(chan struct{})
		listErr error
	)

	// Start workers.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go m.worker(ctx, &wg, jobs, state)
	}

	// Start lister.
	go func() {
		defer close(doneCh)
		listErr = m.listObjects(ctx, bucket, prefix, state, jobs)
	}()

	// Wait for lister to finish, then close jobs channel after workers drain.
	<-doneCh
	close(jobs)
	wg.Wait()

	// Save final state.
	if err := state.Save(m.StateFile); err != nil {
		return fmt.Errorf("failed to save final state: %w", err)
	}

	stats := state.Snapshot()
	if m.DryRun {
		m.Logger.Info("dry-run complete",
			"total_scanned", stats.Total,
			"scanned", stats.Scanned,
			"skipped", stats.Skipped,
			"failed", stats.Failed,
			"class_a", stats.ClassA,
			"class_b", stats.ClassB,
			"class_c_xor", stats.ClassC_XOR,
			"class_c_hkdf", stats.ClassC_HKDF,
			"class_d", stats.ClassD,
			"checkpoint", state.Checkpoint,
		)
	} else {
		m.Logger.Info("migration complete",
			"total_scanned", stats.Total,
			"migrated", stats.Migrated,
			"skipped", stats.Skipped,
			"failed", stats.Failed,
			"class_a", stats.ClassA,
			"class_b", stats.ClassB,
			"class_c_xor", stats.ClassC_XOR,
			"class_c_hkdf", stats.ClassC_HKDF,
			"class_d", stats.ClassD,
			"checkpoint", state.Checkpoint,
		)
	}

	if listErr != nil {
		return fmt.Errorf("listing error: %w", listErr)
	}
	if stats.Failed > 0 {
		return fmt.Errorf("partial migration: %d objects failed (see state file)", stats.Failed)
	}
	return nil
}

// BackfillLegacyNoAAD performs a metadata-only pass that adds the
// MetaLegacyNoAAD="true" marker to objects that were encrypted before AAD was
// introduced AND before SEC-4 added the marker — i.e. objects where both:
//   - x-amz-meta-encrypted = "true"
//   - x-amz-meta-enc-legacy-no-aad is absent (so the no-AAD fallback is
//     currently blocked and the object would fail to decrypt)
//
// This is implemented as a CopyObject-to-self with updated metadata.
// No object body is downloaded or re-encrypted; this is purely a metadata
// operation.  The function is idempotent: objects that already carry the
// marker are skipped.
//
// After backfilling, the normal CLASS B migration path (decrypt no-AAD →
// re-encrypt with AAD → remove marker) can proceed.
func (m *Migrator) BackfillLegacyNoAAD(ctx context.Context, bucket, prefix string) error {
	if m.Logger == nil {
		m.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	m.Logger.Info("backfill-legacy-no-aad starting",
		"bucket", bucket,
		"prefix", prefix,
		"dry_run", m.DryRun,
	)

	if err := m.probeS3(ctx, bucket); err != nil {
		return err
	}

	workers := m.Workers
	if workers <= 0 {
		workers = 4
	}

	type backfillJob struct {
		key  string
		meta map[string]string
	}

	var (
		total   int64
		tagged  int64
		skipped int64
		failed  int64
		mu      sync.Mutex
	)

	addResult := func(t, tag, skip, fail int64) {
		mu.Lock()
		total += t
		tagged += tag
		skipped += skip
		failed += fail
		mu.Unlock()
	}

	jobs := make(chan backfillJob, workers*2)
	var wg sync.WaitGroup

	// Workers: each receives a pre-classified candidate and either
	// logs (dry-run) or issues a CopyObject-to-self.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if m.DryRun {
					m.Logger.Info("dry-run: would backfill", "key", job.key)
					addResult(0, 1, 0, 0)
					continue
				}

				newMeta := make(map[string]string, len(job.meta)+1)
				for k, v := range job.meta {
					newMeta[k] = v
				}
				newMeta[crypto.MetaLegacyNoAAD] = "true"

				if _, _, err := m.S3Client.CopyObject(ctx, bucket, job.key, bucket, job.key, nil, newMeta, nil); err != nil {
					m.Logger.Error("copy-object (backfill) failed", "key", job.key, "error", err)
					addResult(0, 0, 0, 1)
					continue
				}

				m.Logger.Info("backfilled", "key", job.key)
				addResult(0, 1, 0, 0)
			}
		}()
	}

	// Lister: HeadObject + classify on the calling goroutine; send candidates to workers.
	listErr := func() error {
		defer close(jobs)
		opts := s3.ListOptions{MaxKeys: 1000}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result, err := m.S3Client.ListObjects(ctx, bucket, prefix, opts)
			if err != nil {
				return fmt.Errorf("ListObjects failed: %w", err)
			}

			for _, obj := range result.Objects {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				meta, err := m.S3Client.HeadObject(ctx, bucket, obj.Key, nil)
				if err != nil {
					m.Logger.Warn("head failed", "key", obj.Key, "error", err)
					addResult(1, 0, 0, 1)
					continue
				}

				addResult(1, 0, 0, 0)

				// Skip plaintext objects.
				if meta[crypto.MetaEncrypted] != "true" && meta["x-amz-meta-e"] != "true" {
					addResult(0, 0, 1, 0)
					continue
				}

				// Already has the marker — nothing to do.
				if meta[crypto.MetaLegacyNoAAD] == "true" {
					addResult(0, 0, 1, 0)
					continue
				}

				// Only non-chunked, non-fallback objects are CLASS B candidates.
				// Chunked and fallback objects went through different code paths
				// and cannot be pre-AAD single-AEAD objects.
				if meta[crypto.MetaChunkedFormat] == "true" || meta[crypto.MetaFallbackMode] == "true" {
					addResult(0, 0, 1, 0)
					continue
				}

				// This object passes all HEAD-only filters — it is a CLASS B
				// candidate.  No body download needed; send to worker.
				select {
				case jobs <- backfillJob{key: obj.Key, meta: meta}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			if !result.IsTruncated || result.NextContinuationToken == "" {
				break
			}
			opts.ContinuationToken = result.NextContinuationToken
		}
		return nil
	}()

	wg.Wait()

	m.Logger.Info("backfill-legacy-no-aad complete",
		"total_inspected", total,
		"tagged", tagged,
		"skipped", skipped,
		"failed", failed,
		"dry_run", m.DryRun,
	)

	if listErr != nil {
		return listErr
	}
	if failed > 0 {
		return fmt.Errorf("backfill partial: %d objects failed", failed)
	}
	return nil
}



func (m *Migrator) validateGatewayVersion() error {
	switch m.GatewayVersion {
	case "0.6.4", "0.7.0":
		return nil
	default:
		return fmt.Errorf("unsupported gateway version %q (supported: 0.6.4, 0.7.0)", m.GatewayVersion)
	}
}

func (m *Migrator) probeS3(ctx context.Context, bucket string) error {
	if m.S3Client == nil {
		return fmt.Errorf("S3Client is nil")
	}
	// Use ListObjects with a tiny limit to verify connectivity and bucket existence.
	_, err := m.S3Client.ListObjects(ctx, bucket, "", s3.ListOptions{MaxKeys: 1})
	if err != nil {
		return fmt.Errorf("S3 probe failed for bucket %q: %w", bucket, err)
	}
	return nil
}

type migrateJob struct {
	bucket string
	key    string
	class  ObjectClass
}

func (m *Migrator) listObjects(ctx context.Context, bucket, prefix string, state *State, jobs chan<- migrateJob) error {
	opts := s3.ListOptions{
		MaxKeys: 1000,
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := m.S3Client.ListObjects(ctx, bucket, prefix, opts)
		if err != nil {
			return fmt.Errorf("ListObjects failed: %w", err)
		}

		for _, obj := range result.Objects {
			if state.IsCompleted(obj.Key) {
				state.MarkSkipped()
				continue
			}

			meta, err := m.S3Client.HeadObject(ctx, bucket, obj.Key, nil)
			if err != nil {
				m.Logger.Warn("head object failed", "key", obj.Key, "error", err)
				state.MarkFailed(obj.Key, fmt.Sprintf("head failed: %v", err))
				continue
			}

			class := ClassifyObject(meta)
			state.Stats.Total++

			// ClassModern objects with an explicit SourceIterations KDF params
			// value also need re-encryption when FilterKDF is active and
			// SourceIterations is configured. This covers objects written by a
			// gateway configured with a non-default (e.g. 100k) PBKDF2 count
			// that stored MetaKDFParams explicitly.
			if class == ClassModern && m.Filter == FilterKDF && m.SourceIterations > 0 {
				srcParams := crypto.FormatKDFParams(crypto.DefaultKDFParams(m.SourceIterations))
				if meta[crypto.MetaKDFParams] == srcParams {
					class = ClassD_LegacyKDF
				}
			}

			if !NeedsMigration(class) {
				state.MarkSkipped()
				continue
			}

			if !m.Filter.IsAllowed(class) {
				state.MarkSkipped()
				continue
			}

			state.MarkClass(class)

			select {
			case jobs <- migrateJob{bucket: bucket, key: obj.Key, class: class}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if !result.IsTruncated || result.NextContinuationToken == "" {
			break
		}
		opts.ContinuationToken = result.NextContinuationToken
	}

	return nil
}

func (m *Migrator) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan migrateJob, state *State) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := m.migrateObject(ctx, job.bucket, job.key, job.class); err != nil {
			m.Logger.Error("migration failed", "key", job.key, "error", err)
			state.MarkFailed(job.key, err.Error())
			continue
		}

		if m.DryRun {
			state.MarkScanned(job.key)
		} else {
			state.MarkDone(job.key)
		}
	}
}
