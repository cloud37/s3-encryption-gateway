// Backblaze B2 external provider registration.
//
// Activated when B2_ACCESS_KEY_ID, B2_SECRET_ACCESS_KEY, and B2_BUCKET_NAME
// are all set.
package provider

import "os"

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" {
		return
	}
	ak := os.Getenv("B2_ACCESS_KEY_ID")
	sk := os.Getenv("B2_SECRET_ACCESS_KEY")
	bk := os.Getenv("B2_BUCKET_NAME")
	if ak == "" || sk == "" || bk == "" {
		return
	}
	Register(&externalProvider{
		name:      "backblaze-b2",
		endpoint:  envOr("B2_ENDPOINT", "https://s3.eu-central-003.backblazeb2.com"),
		region:    envOr("B2_REGION", "eu-central-003"),
		keyEnv:    "B2_ACCESS_KEY_ID",
		secretEnv: "B2_SECRET_ACCESS_KEY",
		bucketEnv: "B2_BUCKET_NAME",
		caps: CapMultipartUpload | CapMultipartCopy |
			CapObjectTagging | CapPresignedURL |
			CapBatchDelete | CapKMSIntegration | CapEncryptedMPU |
			CapSDKAWSGoV2 | CapSDKBoto3 | CapCLIAWSCLI | CapCLIS5cmd,
		cleanup: CleanupPolicyDelete, // B2 deletes are free
	})
}
