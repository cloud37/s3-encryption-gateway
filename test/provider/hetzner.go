// Hetzner Object Storage external provider registration.
//
// Activated when HETZNER_ACCESS_KEY_ID, HETZNER_SECRET_ACCESS_KEY, and
// HETZNER_BUCKET_NAME are all set.
package provider

import "os"

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" {
		return
	}
	ak := os.Getenv("HETZNER_ACCESS_KEY_ID")
	sk := os.Getenv("HETZNER_SECRET_ACCESS_KEY")
	bk := os.Getenv("HETZNER_BUCKET_NAME")
	if ak == "" || sk == "" || bk == "" {
		return
	}
	// #nosec G101 — test provider registration; values are env var names and default endpoints, not secrets
	Register(&externalProvider{
		name:      "hetzner",
		endpoint:  envOr("HETZNER_ENDPOINT", "https://fsn1.your-objectstorage.com"),
		region:    envOr("HETZNER_REGION", "fsn1"),
		keyEnv:    "HETZNER_ACCESS_KEY_ID",
		secretEnv: "HETZNER_SECRET_ACCESS_KEY",
		bucketEnv: "HETZNER_BUCKET_NAME",
		caps: CapMultipartUpload | CapMultipartCopy |
			CapObjectTagging | CapInlinePutTagging | CapPresignedURL | CapBatchDelete | CapEncryptedMPU,
		cleanup: CleanupPolicyDelete,
	})
}
