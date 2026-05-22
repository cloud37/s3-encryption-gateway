package migrate

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// DryRunReport holds the results of a dry-run classification scan.
type DryRunReport struct {
	Total       int64            `json:"total"`
	Modern      int64            `json:"modern"`
	Plaintext   int64            `json:"plaintext"`
	ClassA      int64            `json:"class_a"`
	ClassB      int64            `json:"class_b"`
	ClassC_XOR  int64            `json:"class_c_xor"`
	ClassC_HKDF int64            `json:"class_c_hkdf"`
	ClassD      int64            `json:"class_d"`
	Unknown     int64            `json:"unknown"`
	Samples     map[string][]string `json:"samples,omitempty"` // up to 10 keys per class
}

// DryRunScan performs a classification-only pass over a bucket/prefix.
// It never writes and produces a report suitable for operator inspection.
func DryRunScan(ctx context.Context, client S3Client, bucket, prefix string, logger *slog.Logger) (*DryRunReport, error) {
	if logger == nil {
		logger = slog.Default()
	}

	report := &DryRunReport{
		Samples: make(map[string][]string),
	}

	opts := s3ListOptions{MaxKeys: 1000}
	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		result, err := client.ListObjects(ctx, bucket, prefix, s3.ListOptions{MaxKeys: opts.MaxKeys, ContinuationToken: opts.ContinuationToken, Delimiter: opts.Delimiter})
		if err != nil {
			return report, fmt.Errorf("ListObjects failed: %w", err)
		}

		for _, obj := range result.Objects {
			meta, err := client.HeadObject(ctx, bucket, obj.Key, nil)
			if err != nil {
				logger.Warn("head object failed during dry-run", "key", obj.Key, "error", err)
				continue
			}

			class := ClassifyObject(meta)
			report.Total++

			switch class {
			case ClassModern:
				report.Modern++
			case ClassPlaintext:
				report.Plaintext++
			case ClassA_XOR:
				report.ClassA++
				addSample(report.Samples, "class_a_xor", obj.Key)
			case ClassB_NoAAD:
				report.ClassB++
				addSample(report.Samples, "class_b_no_aad", obj.Key)
			case ClassC_Fallback_XOR:
				report.ClassC_XOR++
				addSample(report.Samples, "class_c_fallback_xor", obj.Key)
			case ClassC_Fallback_HKDF:
				report.ClassC_HKDF++
				addSample(report.Samples, "class_c_fallback_hkdf", obj.Key)
			case ClassD_LegacyKDF:
				report.ClassD++
				addSample(report.Samples, "class_d_legacy_kdf", obj.Key)
			default:
				report.Unknown++
			}
		}

		if !result.IsTruncated || result.NextContinuationToken == "" {
			break
		}
		opts.ContinuationToken = result.NextContinuationToken
	}

	return report, nil
}

func addSample(samples map[string][]string, class, key string) {
	if len(samples[class]) < 10 {
		samples[class] = append(samples[class], key)
	}
}

// s3ListOptions is a local alias to avoid importing s3 package internals too deeply.
type s3ListOptions struct {
	Delimiter         string
	ContinuationToken string
	MaxKeys           int32
}
