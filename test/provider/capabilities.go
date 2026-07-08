package provider

import "fmt"

// Capabilities is a bitmask of features a Provider supports. Tests call
// t.Skipf when the tested capability bit is absent from the provider's bitmap.
type Capabilities uint64

const (
	// CapObjectLock indicates the backend supports Object Lock / WORM retention.
	CapObjectLock Capabilities = 1 << iota
	// CapObjectTagging indicates support for PutObjectTagging / GetObjectTagging.
	CapObjectTagging
	// CapMultipartUpload indicates support for the S3 multipart upload API.
	CapMultipartUpload
	// CapMultipartCopy indicates support for UploadPartCopy.
	CapMultipartCopy
	// CapVersioning indicates support for bucket versioning.
	CapVersioning
	// CapServerSideEncryption indicates native server-side encryption
	// (SSE-S3 / SSE-KMS). The gateway itself always encrypts client-side;
	// this flag is for backends that also support SSE on top.
	CapServerSideEncryption
	// CapPresignedURL indicates support for pre-signed GET / PUT URLs.
	CapPresignedURL
	// CapConditionalWrites indicates support for If-None-Match / If-Match on PUT.
	CapConditionalWrites
	// CapBatchDelete indicates support for the DeleteObjects (multi-delete)
	// XML batch shape.
	CapBatchDelete
	// CapKMSIntegration indicates that the Cosmian KMS integration works with
	// this provider (i.e. the provider is reachable from the KMS container and
	// vice-versa in the test network).
	CapKMSIntegration
	// CapInlinePutTagging indicates the backend accepts x-amz-tagging as an
	// inline header on PutObject. Backends that only support tagging via the
	// ?tagging subresource (e.g. Backblaze B2) do NOT set this bit; they still
	// set CapObjectTagging to indicate ?tagging subresource support.
	CapInlinePutTagging
	// CapEncryptedMPU indicates that the conformance test for encrypted
	// multipart uploads should run against this provider. All providers that
	// support multipart uploads should set this; the test itself starts a
	// Valkey container for state storage (Docker required).
	CapEncryptedMPU
	// CapLoadTest indicates that the provider is suitable for in-process load
	// tests (range and multipart throughput/concurrency checks). Providers with
	// high per-request latency (external/cloud) skip these to keep CI fast.
	CapLoadTest
	// CapBucketPolicy indicates support for PutBucketPolicy / GetBucketPolicy.
	CapBucketPolicy
	// CapBucketLifecycle indicates support for PutBucketLifecycle / GetBucketLifecycle.
	CapBucketLifecycle
	// CapBucketCors indicates support for PutBucketCors / GetBucketCors.
	CapBucketCors
	// CapBucketACL indicates support for PutBucketAcl / GetBucketAcl.
	CapBucketACL
	// CapObjectACL indicates support for PutObjectAcl / GetObjectAcl.
	CapObjectACL
	// CapBucketEncryption indicates support for PutBucketEncryption / GetBucketEncryption.
	CapBucketEncryption

	// V1.0-COMPAT-1 — SDK/Tool compatibility matrix capability bits.

	// CapSDKAWSGoV2 indicates the provider is suitable for the AWS SDK Go v2
	// smoke test. Set on all local providers and external AWS S3.
	CapSDKAWSGoV2 Capabilities = 1 << 20

	// CapSDKBoto3 indicates the provider is suitable for the boto3 (Python)
	// smoke test. Requires Docker (Python container).
	CapSDKBoto3 Capabilities = 1 << 21

	// CapCLIAWSCLI indicates the provider is suitable for the awscli smoke test.
	// Requires Docker (awscli container).
	CapCLIAWSCLI Capabilities = 1 << 22

	// CapCLIS5cmd indicates the provider is suitable for the s5cmd smoke test.
	// Requires Docker (s5cmd container).
	CapCLIS5cmd Capabilities = 1 << 23

	// CapCLIRclone indicates the provider is suitable for the rclone smoke test.
	// Requires Docker (rclone container).
	CapCLIRclone Capabilities = 1 << 24

	// CapSDKMinIOPy indicates the provider is suitable for the minio-py (Python)
	// smoke test. Requires Docker (Python container).
	CapSDKMinIOPy Capabilities = 1 << 25

	// CapCLIRestic indicates the provider is suitable for the restic conformance
	// test that exercises V1.0-CONFIG-1 bypass-encryption with a real restic
	// container (restic/restic). The bypass policy is enabled inside the test
	// itself; this bit only declares that the provider can host restic's S3
	// workflow (ListObjectsV2 + PutObject + multipart upload + DeleteObjects).
	// Requires Docker (restic container with --network=host).
	CapCLIRestic Capabilities = 1 << 26

	// CapSizeTranslation indicates that the conformance test for the
	// ListObjects size cache (V1.0-S3-3) should run against this provider.
	// Requires Docker for a Valkey container. All providers that support
	// multipart uploads should set this; the test itself starts a Valkey
	// container for size cache state storage.
	CapSizeTranslation Capabilities = 1 << 27

	// Next available: 1 << 28
)

// capNames maps each bit to a human-readable label for Stringer output.
var capNames = []struct {
	bit  Capabilities
	name string
}{
	{CapObjectLock, "ObjectLock"},
	{CapObjectTagging, "ObjectTagging"},
	{CapMultipartUpload, "MultipartUpload"},
	{CapMultipartCopy, "MultipartCopy"},
	{CapVersioning, "Versioning"},
	{CapServerSideEncryption, "SSE"},
	{CapPresignedURL, "PresignedURL"},
	{CapConditionalWrites, "ConditionalWrites"},
	{CapBatchDelete, "BatchDelete"},
	{CapKMSIntegration, "KMSIntegration"},
	{CapInlinePutTagging, "InlinePutTagging"},
	{CapEncryptedMPU, "EncryptedMPU"},
	{CapLoadTest, "LoadTest"},
	{CapBucketPolicy, "BucketPolicy"},
	{CapBucketLifecycle, "BucketLifecycle"},
	{CapBucketCors, "BucketCors"},
	{CapBucketACL, "BucketACL"},
	{CapObjectACL, "ObjectACL"},
	{CapBucketEncryption, "BucketEncryption"},
	{CapSizeTranslation, "SizeTranslation"},

	// V1.0-COMPAT-1 — SDK/Tool compatibility matrix.
	{CapSDKAWSGoV2, "SDKAWSGoV2"},
	{CapSDKBoto3, "SDKBoto3"},
	{CapCLIAWSCLI, "CLIAWSCLI"},
	{CapCLIS5cmd, "CLIS5cmd"},
	{CapCLIRclone, "CLIRclone"},
	{CapSDKMinIOPy, "SDKMinIOPy"},
	{CapCLIRestic, "CLIRestic"},
}

// String returns a human-readable description of the capabilities bitmap.
func (c Capabilities) String() string {
	if c == 0 {
		return "none"
	}
	var out string
	for _, cn := range capNames {
		if c&cn.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += cn.name
		}
	}
	if out == "" {
		return fmt.Sprintf("unknown(0x%x)", uint64(c))
	}
	return out
}
