package audit

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// VerifyKey retrieves the recorded key version metadata for an object and,
// when a desired version is specified, reports a match/mismatch.
// No full body decryption is performed.
func VerifyKey(ctx context.Context, client AuditClient, bucket, key string, wantVersion *int) (*VerifyKeyReport, error) {
	meta, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		return nil, fmt.Errorf("verify-key: %s/%s: %w", bucket, key, err)
	}

	recorded := meta[crypto.MetaKeyVersion]
	class := ClassifyObject(meta)

	report := &VerifyKeyReport{
		Bucket:   bucket,
		Key:      key,
		Recorded: recorded,
		Class:    ClassToString(class),
	}

	if wantVersion != nil {
		report.Want = strconv.Itoa(*wantVersion)
		report.Match = recorded == report.Want

		// Attempt unwrap if key version matches and we have an engine path
		// available. For now, metadata-only verification is the default.
		// Full unwrap verification will be added when KMS adapters land.
		if report.Match {
			report.Verified = "metadata-only"
		} else {
			report.Verified = "mismatch"
		}
	} else {
		// No requested version — just report the recorded value
		report.Match = true
		report.Verified = "metadata-only"
	}

	return report, nil
}
