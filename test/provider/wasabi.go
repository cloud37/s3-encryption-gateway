// Wasabi external provider registration.
//
// Activated when WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, and
// WASABI_BUCKET_NAME are all set.
//
// CleanupPolicy is SkipDelete because Wasabi charges a minimum 90-day storage
// duration; deleting before TTL costs the same as keeping. Objects are left for
// Wasabi's own lifecycle policy.
package provider

import "os"

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" {
		return
	}
	ak := os.Getenv("WASABI_ACCESS_KEY_ID")
	sk := os.Getenv("WASABI_SECRET_ACCESS_KEY")
	bk := os.Getenv("WASABI_BUCKET_NAME")
	if ak == "" || sk == "" || bk == "" {
		return
	}
	Register(&externalProvider{
		name:      "wasabi",
		endpoint:  envOr("WASABI_ENDPOINT", "https://s3.wasabisys.com"),
		region:    envOr("WASABI_REGION", "us-east-1"),
		keyEnv:    "WASABI_ACCESS_KEY_ID",
		secretEnv: "WASABI_SECRET_ACCESS_KEY",
		bucketEnv: "WASABI_BUCKET_NAME",
		caps: CapMultipartUpload | CapMultipartCopy |
			CapObjectTagging | CapInlinePutTagging | CapPresignedURL |
			CapBatchDelete | CapEncryptedMPU,
		cleanup: CleanupPolicySkipDelete, // 90-day minimum
	})
}
