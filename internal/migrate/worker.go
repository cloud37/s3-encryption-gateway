package migrate

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// migrateObject performs the decrypt→re-encrypt→write cycle for a single object.
// In dry-run mode it only reads and classifies, without writing.
func (m *Migrator) migrateObject(ctx context.Context, bucket, key string, class ObjectClass) error {
	if m.DryRun {
		// In dry-run mode the object was already classified via HeadObject
		// during listing — no further I/O is needed or permitted.
		return nil
	}

	// Step 1: GetObject
	reader, meta, err := m.S3Client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		return fmt.Errorf("get object failed: %w", err)
	}
	defer reader.Close()

	// Step 2: Decrypt with source engine
	plaintextReader, decMeta, err := m.SourceEngine.Decrypt(ctx, reader, meta)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	// Step 3: Re-encrypt with target engine (pass original user metadata)
	userMeta := filterUserMetadata(decMeta)
	encryptedReader, encMeta, err := m.TargetEngine.Encrypt(ctx, plaintextReader, userMeta)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	// Step 4: Buffer encrypted stream to a temporary file so the S3 client
	// receives a seekable body (required by AWS SDK v2 SigV4 payload hashing).
	encFile, err := bufferToTempFile(encryptedReader)
	if err != nil {
		return fmt.Errorf("buffer encrypted data: %w", err)
	}
	defer func() {
		encFile.Close()
		_ = os.Remove(encFile.Name())
	}()
	fi, _ := encFile.Stat()
	contentLength := fi.Size()

	// Step 5: PutObject (atomic overwrite)
	if err := m.S3Client.PutObject(ctx, bucket, key, encFile, encMeta, &contentLength, "", nil, "", "", "", "", ""); err != nil {
		return fmt.Errorf("put object failed: %w", err)
	}

	// Step 6: Verify (optional)
	if m.Verify {
		if err := m.verifyObject(ctx, bucket, key); err != nil {
			return fmt.Errorf("verify failed: %w", err)
		}
	}

	// Step 7: Companion object cleanup (best-effort for fallback objects)
	if class == ClassC_Fallback_XOR || class == ClassC_Fallback_HKDF {
		if ptr := meta[crypto.MetaFallbackPointer]; ptr != "" {
			if delErr := m.S3Client.DeleteObject(ctx, bucket, ptr, nil); delErr != nil {
				if m.Logger != nil {
					m.Logger.Warn("companion delete failed (best-effort)",
						"key", key, "companion", ptr, "error", delErr)
				}
			}
		}
	}

	return nil
}

// bufferToTempFile drains src into a temporary file and returns the file
// positioned at offset 0.  The caller is responsible for closing and deleting
// the file.  This is required because the AWS SDK v2 SigV4 signer needs a
// seekable body to compute the payload hash.
func bufferToTempFile(src io.Reader) (*os.File, error) {
	f, err := os.CreateTemp("", "s3eg-migrate-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("seek temp file: %w", err)
	}
	return f, nil
}

// verifyObject re-reads the just-written object and decrypts it with the
// target engine to ensure correctness.
func (m *Migrator) verifyObject(ctx context.Context, bucket, key string) error {
	// Small delay for distributed MinIO eventual consistency.
	if m.VerifyDelay > 0 {
		select {
		case <-time.After(m.VerifyDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	reader, meta, err := m.S3Client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		return fmt.Errorf("verify get failed: %w", err)
	}
	defer reader.Close()

	_, _, err = m.TargetEngine.Decrypt(ctx, reader, meta)
	if err != nil {
		return fmt.Errorf("verify decrypt failed: %w", err)
	}
	return nil
}

// filterUserMetadata strips encryption and compression markers from metadata,
// leaving only user-supplied metadata to be passed to the target encrypt.
func filterUserMetadata(meta map[string]string) map[string]string {
	if meta == nil {
		return nil
	}
	userMeta := make(map[string]string, len(meta))
	for k, v := range meta {
		if crypto.IsEncryptionMetadata(k) || crypto.IsCompressionMetadata(k) {
			continue
		}
		userMeta[k] = v
	}
	return userMeta
}
