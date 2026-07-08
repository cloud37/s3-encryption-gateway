// AWS S3 external provider registration.
//
// Activated when AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and
// AWS_BUCKET_NAME are all set. This file is the canonical worked example
// that new vendor plug-ins copy and adapt.
package provider

import "os"

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" {
		return
	}
	ak := os.Getenv("AWS_ACCESS_KEY_ID")
	sk := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bk := os.Getenv("AWS_BUCKET_NAME")
	if ak == "" || sk == "" || bk == "" {
		return // credentials not set; skip silently
	}
	// #nosec G101 — test provider registration; values are env var names and default endpoints, not secrets
	Register(&externalProvider{
		name:      "aws",
		endpoint:  "", // use SDK default (virtual-hosted style)
		region:    envOr("AWS_REGION", "us-east-1"),
		keyEnv:    "AWS_ACCESS_KEY_ID",
		secretEnv: "AWS_SECRET_ACCESS_KEY",
		bucketEnv: "AWS_BUCKET_NAME",
		caps: CapMultipartUpload | CapMultipartCopy |
			CapObjectTagging | CapInlinePutTagging | CapPresignedURL |
			CapConditionalWrites | CapBatchDelete |
			CapObjectLock | CapVersioning |
			CapServerSideEncryption | CapKMSIntegration | CapSizeTranslation | CapEncryptedMPU |
			CapSDKAWSGoV2 | CapSDKBoto3 | CapCLIAWSCLI |
			CapCLIS5cmd | CapCLIRclone | CapSDKMinIOPy | CapCLIRestic,
		cleanup: CleanupPolicyDelete,
	})
}
