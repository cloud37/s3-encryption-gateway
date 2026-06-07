package audit

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// algorithmCounts aggregates encryption algorithm counts.
type algorithmCounts struct {
	mu         sync.Mutex
	total      int64
	algorithms map[string]int64
	classes    map[string]int64
}

func newAlgorithmCounts() *algorithmCounts {
	return &algorithmCounts{
		algorithms: make(map[string]int64),
		classes:    make(map[string]int64),
	}
}

func (ac *algorithmCounts) add(alg, class string) {
	ac.mu.Lock()
	ac.total++
	ac.algorithms[alg]++
	ac.classes[class]++
	ac.mu.Unlock()
}

// ListAlgorithm scans objects in a bucket/prefix, classifies each, and
// returns the distribution of encryption algorithms and object classes.
// It uses a read-only worker pool (channels, no writes) with the specified
// number of concurrent workers.
func ListAlgorithm(ctx context.Context, client AuditClient, bucket, prefix string, workers int) (*AlgorithmReport, error) {
	if workers <= 0 {
		workers = 4
	}

	type headJob struct {
		key string
	}

	counts := newAlgorithmCounts()

	jobs := make(chan headJob, workers*2)
	var wg sync.WaitGroup

	// Start workers: each receives a key, performs HeadObject, classifies.
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

				meta, err := client.HeadObject(ctx, bucket, job.key, nil)
				if err != nil {
					// Skip objects we cannot read; counting failures is
					// intentionally avoided for this read-only scan.
					continue
				}

				class := ClassifyObject(meta)
				alg := meta[crypto.MetaAlgorithm]

				if alg == "" && class == ClassPlaintext {
					alg = "(plaintext)"
				} else if alg == "" {
					alg = "(unknown)"
				}

				counts.add(alg, ClassToString(class))
			}
		}()
	}

	// Lister: paginated ListObjectsV2, sending keys to workers.
	listErr := func() error {
		defer close(jobs)
		opts := s3.ListOptions{MaxKeys: 1000}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result, err := client.ListObjects(ctx, bucket, prefix, opts)
			if err != nil {
				return fmt.Errorf("ListObjects failed: %w", err)
			}

			for _, obj := range result.Objects {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				select {
				case jobs <- headJob{key: obj.Key}:
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

	if listErr != nil {
		return nil, listErr
	}

	// Build report
	report := &AlgorithmReport{
		Bucket:  bucket,
		Prefix:  prefix,
		Total:   counts.total,
		ByClass: counts.classes,
	}

	// Sort by count descending
	type algEntry struct {
		name  string
		count int64
	}
	var entries []algEntry
	for name, count := range counts.algorithms {
		entries = append(entries, algEntry{name: name, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	for _, e := range entries {
		pct := 0.0
		if counts.total > 0 {
			pct = float64(e.count) / float64(counts.total) * 100
		}
		report.ByAlgorithm = append(report.ByAlgorithm, AlgorithmReportItem{
			Algorithm: e.name,
			Count:     e.count,
			Percent:   pct,
		})
	}

	return report, nil
}
