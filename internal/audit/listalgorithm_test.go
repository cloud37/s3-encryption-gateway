package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

const testBucket = "testbucket"

func TestListAlgorithm_AggregatesCountsAndPct(t *testing.T) {
	mock := newMockAuditClient()

	// Add 4 AES256-GCM objects (modern)
	for i := 0; i < 4; i++ {
		key := aesKey(i)
		mock.addObject(key, []byte("data"), map[string]string{
			crypto.MetaEncrypted: "true",
			crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
			crypto.MetaKDFParams: "pbkdf2-sha256:600000",
		})
	}

	// Add 1 ChaCha20-Poly1305 object (modern)
	mock.addObject(chachaKey(0), []byte("data"), map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmChaCha20Poly1305,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	})

	// Add 1 plaintext object
	mock.addObject(plainKey(0), []byte("plaintext data"), map[string]string{
		"Content-Type": "text/plain",
	})

	report, err := ListAlgorithm(context.Background(), mock, testBucket, "", 2)
	if err != nil {
		t.Fatalf("ListAlgorithm failed: %v", err)
	}

	if report.Total != 6 {
		t.Errorf("Total = %d, want 6", report.Total)
	}

	// Check algorithm distribution
	algMap := make(map[string]int64)
	for _, item := range report.ByAlgorithm {
		algMap[item.Algorithm] = item.Count
	}

	if algMap[crypto.AlgorithmAES256GCM] != 4 {
		t.Errorf("AES256-GCM count = %d, want 4", algMap[crypto.AlgorithmAES256GCM])
	}
	if algMap[crypto.AlgorithmChaCha20Poly1305] != 1 {
		t.Errorf("ChaCha20-Poly1305 count = %d, want 1", algMap[crypto.AlgorithmChaCha20Poly1305])
	}
	if algMap["(plaintext)"] != 1 {
		t.Errorf("plaintext count = %d, want 1", algMap["(plaintext)"])
	}

	// Verify percentages
	for _, item := range report.ByAlgorithm {
		switch item.Algorithm {
		case crypto.AlgorithmAES256GCM:
			if item.Percent < 66 || item.Percent > 67 {
				t.Errorf("AES256-GCM percent = %.2f%%, want ~66.67%%", item.Percent)
			}
		case crypto.AlgorithmChaCha20Poly1305:
			if item.Percent < 16 || item.Percent > 17 {
				t.Errorf("ChaCha20-Poly1305 percent = %.2f%%, want ~16.67%%", item.Percent)
			}
		}
	}

	// Check class distribution
	if report.ByClass["modern"] != 5 {
		t.Errorf("class 'modern' count = %d, want 5", report.ByClass["modern"])
	}
	if report.ByClass["plaintext"] != 1 {
		t.Errorf("class 'plaintext' count = %d, want 1", report.ByClass["plaintext"])
	}
}

func TestListAlgorithm_EmptyBucket(t *testing.T) {
	mock := newMockAuditClient()

	report, err := ListAlgorithm(context.Background(), mock, testBucket, "", 2)
	if err != nil {
		t.Fatalf("ListAlgorithm failed: %v", err)
	}

	if report.Total != 0 {
		t.Errorf("Total = %d, want 0", report.Total)
	}
}

func TestListAlgorithm_PrefixFilter(t *testing.T) {
	mock := newMockAuditClient()

	mock.addObject(testBucket+"/logs/2024/01/data", []byte("data"), map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	})
	mock.addObject(testBucket+"/logs/2024/02/data", []byte("data"), map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	})
	mock.addObject(testBucket+"/other/data", []byte("data"), map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	})

	report, err := ListAlgorithm(context.Background(), mock, testBucket, "logs/", 2)
	if err != nil {
		t.Fatalf("ListAlgorithm failed: %v", err)
	}

	if report.Total != 2 {
		t.Errorf("Total = %d, want 2 (only objects under logs/ prefix)", report.Total)
	}
	if report.Prefix != "logs/" {
		t.Errorf("Prefix = %q, want logs/", report.Prefix)
	}
}

func TestListAlgorithm_WorkersParameter(t *testing.T) {
	mock := newMockAuditClient()

	// Add some objects
	for i := 0; i < 10; i++ {
		key := aesKey(i)
		mock.addObject(key, []byte("data"), map[string]string{
			crypto.MetaEncrypted: "true",
			crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
			crypto.MetaKDFParams: "pbkdf2-sha256:600000",
		})
	}

	// Test with different worker counts
	report, err := ListAlgorithm(context.Background(), mock, testBucket, "", 1)
	if err != nil {
		t.Fatalf("ListAlgorithm(workers=1) failed: %v", err)
	}
	if report.Total != 10 {
		t.Errorf("Total = %d, want 10", report.Total)
	}

	report, err = ListAlgorithm(context.Background(), mock, testBucket, "", 8)
	if err != nil {
		t.Fatalf("ListAlgorithm(workers=8) failed: %v", err)
	}
	if report.Total != 10 {
		t.Errorf("Total = %d, want 10", report.Total)
	}
}

// Test helpers

func aesKey(i int) string {
	return testBucket + "/aes-obj-" + itoa(i)
}

func chachaKey(i int) string {
	return testBucket + "/chacha-obj-" + itoa(i)
}

func plainKey(i int) string {
	return testBucket + "/plain-obj-" + itoa(i)
}

func itoa(i int) string {
	return strings.TrimSpace(string(rune('0' + i)))
}
