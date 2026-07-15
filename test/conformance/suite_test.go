//go:build conformance

// Package conformance is the tier-2 multi-provider test suite.
//
// Build tag: conformance (never runs under default `go test ./...`).
//
// Run via:
//
//	make test-conformance              # all registered providers
//	make test-conformance-minio        # MinIO only (PR gate)
//	make test-conformance-local        # local providers (MinIO + Garage + RustFS)
//	make test-conformance-external     # external providers with credentials
//
// The suite is provider-agnostic: each testXxx function takes
// (t *testing.T, inst provider.Instance) and zero-branches on provider name.
// Capability bits drive t.Skipf when a backend does not support the feature
// under test.
package conformance

import (
	"context"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// TestConformance runs every conformance test case against every registered
// provider. Providers execute concurrently; test cases within a provider
// execute serially (safe to promote to parallel once the suite is stable —
// see open question §4 in the plan).
func TestConformance(t *testing.T) {
	providers := provider.All()
	if len(providers) == 0 {
		t.Skip("No providers registered; set provider credentials or ensure Docker is available")
	}

	for _, p := range providers {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel() // Different providers run concurrently.
			ctx := context.Background()
			inst := p.Start(ctx, t)

			cases := []struct {
				name string
				cap  provider.Capabilities
				fn   func(*testing.T, provider.Instance)
			}{
				// Core object operations — run on every provider.
				{"PutGet", 0, testPutGet},
				{"PutGet_LargeObject", 0, testPutGet_Large},
				{"HeadObject", 0, testHeadObject},
				{"ListObjects", 0, testListObjects},
				{"ListObjectsV1_Pagination", 0, testListObjectsV1_Pagination},
				{"ListObjectsV2_Pagination", 0, testListObjectsV2_Pagination},
				{"ListObjectsV1_SizeAccuracy", 0, testListObjectsV1_SizeAccuracy},
				{"ListObjectsV2_SizeAccuracy", 0, testListObjectsV2_SizeAccuracy},
				{"ListObjectsV1_SizeAccuracy_WarmCache", provider.CapSizeTranslation, testListObjectsV1_SizeAccuracy_WarmCache},
				{"ListObjectsV2_SizeAccuracy_WarmCache", provider.CapSizeTranslation, testListObjectsV2_SizeAccuracy_WarmCache},
				{"ListObjectsV1_SizeAccuracy_MultiPage", provider.CapSizeTranslation, testListObjectsV1_SizeAccuracy_MultiPage},
				{"ListObjectsV2_SizeAccuracy_MultiPage", provider.CapSizeTranslation, testListObjectsV2_SizeAccuracy_MultiPage},
				{"ListObjects_SizeAccuracy_FallbackHead", provider.CapSizeTranslation, testListObjects_SizeAccuracy_FallbackHead},
				{"ListObjects_SizeAccuracy_CacheCoherence", provider.CapSizeTranslation, testListObjects_SizeAccuracy_CacheCoherence},
				{"DeleteObject", 0, testDeleteObject},
				{"DeleteObjects", provider.CapBatchDelete, testDeleteObjects},
				{"CopyObject", 0, testCopyObject},
				{"RangedRead", 0, testRangedRead},
				{"RangedRead_CrossChunk", 0, testRangedRead_CrossChunk},

				// Encryption round-trips (chunked + legacy AEAD).
				{"Chunked_RoundTrip", 0, testChunkedRoundTrip},
				{"Chunked_RangedRead", 0, testChunkedRangedRead},
				{"Legacy_RoundTrip", 0, testLegacyRoundTrip},

				// Multipart operations.
				{"Multipart_Basic", provider.CapMultipartUpload, testMultipartBasic},
				{"Multipart_Abort", provider.CapMultipartUpload, testMultipartAbort},
				{"Multipart_ListParts", provider.CapMultipartUpload, testMultipartListParts},
				{"Multipart_UploadPartETagQuoted", provider.CapMultipartUpload, testMultipartUploadPartETagQuoted},
				{"Multipart_MinIOGo", provider.CapMultipartUpload, testMultipartUploadMinioGo},

				// UploadPartCopy.
				{"UploadPartCopy_Full", provider.CapMultipartCopy, testUPC_Full},
				{"UploadPartCopy_Range", provider.CapMultipartCopy, testUPC_Range},
				{"UploadPartCopy_Plaintext", provider.CapMultipartCopy, testUPC_Plaintext},
				{"UploadPartCopy_Legacy", provider.CapMultipartCopy, testUPC_Legacy},
				{"UploadPartCopy_Mixed", provider.CapMultipartCopy, testUPC_Mixed},
				{"UploadPartCopy_AbortMidway", provider.CapMultipartCopy, testUPC_AbortMidway},
				{"UploadPartCopy_CrossBucket", provider.CapMultipartCopy, testUPC_CrossBucket},

				// Object tagging.
				// Tagging_Passthrough tests the x-amz-tagging header on PutObject
				// (inline tagging). Backends that only support ?tagging subresource
				// (e.g. Backblaze B2) skip this via CapInlinePutTagging.
				{"Tagging_Passthrough", provider.CapInlinePutTagging, testTaggingPassthrough},
				{"Tagging_GetPut", provider.CapObjectTagging, testTaggingGetPut},

				// V1.0-S3-1 ACL and lifecycle header passthrough.
				{"S3Compat_ACLInlinePassthrough", provider.CapObjectACL, testACLInlinePassthrough},
				{"S3Compat_LifecycleHeaderPassthrough", provider.CapBucketLifecycle, testLifecycleHeaderPassthrough},

				// Presigned URLs.
				{"Presigned_Get", provider.CapPresignedURL, testPresignedGet},
				{"Presigned_Put", provider.CapPresignedURL, testPresignedPut},

				// Key rotation — dual-read window, fail-closed, and metrics.
				{"Rotation_DualRead", 0, testRotationDualRead},
				{"Rotation_OldKeyUnreadable", 0, testRotationOldKeyUnreadableAfterRemoval},
				{"Rotation_Metric", 0, testRotationMetric},

				// Object Lock.
				{"ObjectLock_Retention", provider.CapObjectLock, testObjectLockRetention},
				{"ObjectLock_LegalHold", provider.CapObjectLock, testObjectLockLegalHold},
				{"ObjectLock_BypassRefused", provider.CapObjectLock, testObjectLockBypassRefused},

				// Metadata round-trip (catches cipher: authentication failed bugs).
				{"Metadata_RoundTrip", 0, testMetadataRoundTrip},

				// V1.0-CRYPTO-3 encrypted metadata conformance.
				{"EncryptedMetadata_RoundTrip", 0, testEncryptedMetadata_RoundTrip},
				{"EncryptedMetadata_BackwardCompat", 0, testEncryptedMetadata_BackwardCompat},
				{"EncryptedMetadata_ListObjects", 0, testEncryptedMetadata_ListObjects},

				// Concurrent operations.
				{"Concurrent_PutGet", 0, testConcurrentPutGet},

				// V0.6-PERF-1 streaming regression guards.
				// These verify that the zero-copy refactors (Phases B, C, D, E) do not
				// introduce correctness regressions against real backends.
				{"PERF1_CopyObject_LargeChunked", 0, testCopyObject_LargeChunked},
				{"PERF1_ChunkedRangedRead_Large", 0, testChunkedRangedRead_Large},
				{"PERF1_UploadPart_OversizeCap", provider.CapMultipartUpload, testUploadPart_OversizeCap},

				// Encrypted multipart uploads (ADR-0009 / V0.6-SEC-3).
				// Requires Docker for a Valkey container (state store).
				{"EncryptedMPU_RoundTrip", provider.CapEncryptedMPU, testEncryptedMPURoundTrip},
				{"EncryptedMPU_ManifestHiddenAndMissingDiagnostic", provider.CapEncryptedMPU, testEncryptedMPUManifestIsHidden},
				{"EncryptedMPU_AtRest", provider.CapEncryptedMPU, testEncryptedMPU_AtRest},
				{"EncryptedMPU_AbortCleansState", provider.CapEncryptedMPU, testEncryptedMPUAbortCleansState},
				{"EncryptedMPU_LargeObject", provider.CapEncryptedMPU, testEncryptedMPU_LargeObject},

				// V1.0-CONFIG-1 — Per-bucket encryption bypass + ENV policy configuration.
				{"BypassEncryption_RoundTrip", 0, testBypassEncryption_RoundTrip},
				{"BypassEncryption_AtRest", 0, testBypassEncryption_AtRest},
				{"BypassEncryption_NoEncryptionMetadata", 0, testBypassEncryption_NoEncryptionMetadata},
				{"BypassEncryption_EncryptedObjectReturns409", 0, testBypassEncryption_EncryptedObjectReturns409},
				{"BypassEncryption_PlaintextObjectServedCorrectly", 0, testBypassEncryption_PlaintextObjectServedCorrectly},
				{"BypassEncryption_EnvPolicy_EndToEnd", 0, testBypassEncryption_EnvPolicy_EndToEnd},
				{"BypassEncryption_MixedBypassAndEncrypt", 0, testBypassEncryption_MultiPolicy_MixedBypassAndEncrypt},
				{"BypassEncryption_ConflictRejected", 0, testBypassEncryption_ConflictRejected},
				{"BypassEncryption_ResetClearsPolicies", 0, testBypassEncryption_ResetClearsPolicies},

				// V1.0-CONFIG-1 — Restic bypass-encryption conformance (issue #198).
				// These spin up a real restic/restic container and exercise the
				// full init+backup+restore cycle, gated on CapCLIRestic so they
				// only fire on backends known to host the workflow (local +
				// external AWS S3).
				{"BypassEncryption_ResticRoundTrip", provider.CapCLIRestic, testBypassEncryption_ResticRoundTrip},
				{"BypassEncryption_ResticBackupGatewayRestoreDirect", provider.CapCLIRestic, testBypassEncryption_ResticBackupGatewayRestoreDirect},

				// KMS envelope encryption integration test.
				// Starts a Cosmian KMS container and verifies the full wrap/unwrap path
				// with the in-process gateway. Gated on CapKMSIntegration so it only
				// runs on local Testcontainer providers (MinIO, Garage) where the
				// in-process gateway can reach the KMS container.
				{"KMS_EnvelopeEncryption", provider.CapKMSIntegration, testKMSIntegration},

				// V1.0-KMS-3 — OpenBao / Vault Transit adapter conformance.
				// Starts a real OpenBao dev-server container and exercises the
				// full wrap/unwrap path through the in-process gateway proxy.
				// Gated on CapOpenBaoKMS; disable with GATEWAY_TEST_SKIP_OPENBAO=1.
				{"OpenBao_EnvelopeEncryption", provider.CapOpenBaoKMS, testOpenBaoKMSIntegration},
				{"OpenBao_KeyRotation", provider.CapOpenBaoKMS, testOpenBaoKMSRotation},
				{"OpenBao_TokenRenewal", provider.CapOpenBaoKMS, testOpenBaoKMSTokenRenewal},
				{"SelfContained_AES_EnvelopeRoundTrip", 0, testSelfContained_AES_EnvelopeRoundTrip},
				{"SelfContained_AES_AtRest", 0, testSelfContained_AES_AtRest},
				{"SelfContained_AES_Rotation_DualRead", 0, testSelfContained_AES_Rotation_DualRead},
				{"SelfContained_AES_RangedGet_LargeChunked", 0, testSelfContained_AES_RangedGet_LargeChunked},
				{"SelfContained_RSA_EnvelopeRoundTrip", 0, testSelfContained_RSA_EnvelopeRoundTrip},
				{"SelfContained_RSA_AtRest", 0, testSelfContained_RSA_AtRest},
				{"SelfContained_RSA_RangedGet", 0, testSelfContained_RSA_RangedGet},

				// Self-contained KEK + encrypted MPU (Gap 1 & 2: AES KEK with MPU).
				// Requires Docker for a Valkey container (MPU state store).
				{"SelfContained_AES_EncryptedMPU_RoundTrip", provider.CapEncryptedMPU, testSelfContained_AES_EncryptedMPU_RoundTrip},
				{"SelfContained_AES_EncryptedMPU_RangedGet", provider.CapEncryptedMPU, testSelfContained_AES_EncryptedMPU_RangedGet},
				{"SelfContained_AES_EncryptedMPU_AtRest", provider.CapEncryptedMPU, testSelfContained_AES_EncryptedMPU_AtRest},
				{"SelfContained_AES_Rotation_EncryptedMPU", provider.CapEncryptedMPU, testSelfContained_AES_Rotation_EncryptedMPU},
				// Gap 4: FallbackKeyManager end-to-end upgrade scenario.
				{"FallbackKeyManager_EncryptedMPU_LegacyUpgrade", provider.CapEncryptedMPU, testFallbackKeyManager_EncryptedMPU_LegacyUpgrade},

				// In-process load tests (range concurrency + multipart throughput).
				// Only run against local providers (MinIO, Garage) where per-request
				// latency is low enough for meaningful QPS assertions.
				{"Load_RangeRead", provider.CapLoadTest, testRangeLoad},
				{"Load_Multipart", provider.CapLoadTest | provider.CapMultipartUpload, testMultipartLoad},

				// Chaos tests — in-process ToxicServer, no real S3 backend used.
				// Gated on CapLoadTest so they only run on local providers (once
				// per provider is sufficient; the backend is a fake anyway).
				{"Chaos_Throttling", provider.CapLoadTest, testChaosThrottling},
				{"Chaos_Backend500", provider.CapLoadTest, testChaosBackend500},
				{"Chaos_NetworkTimeout", provider.CapLoadTest, testChaosNetworkTimeout},

				// V0.6-PERF-2 retry policy conformance — cap=0, runs on every provider.
				// These use an in-process ToxicServer backend so no Docker is required.
				// They verify Prometheus metric emission end-to-end (not just unit-test level).
				{"PERF2_Retry_503_MetricEmitted", 0, testRetry_TransientBackend503_MetricEmitted},
				{"PERF2_Retry_429_MetricEmitted", 0, testRetry_TransientBackend429_MetricEmitted},
				{"PERF2_Retry_GiveUp_MetricEmitted", 0, testRetry_PersistentFailure_GiveUpMetricEmitted},
				{"PERF2_Retry_BackoffHistogram", 0, testRetry_BackoffHistogramPopulated},
				{"PERF2_Retry_AttemptsHistogram", 0, testRetry_AttemptsHistogramPopulated},
				{"PERF2_Retry_MaxAttemptsRespected", 0, testRetry_MaxAttemptsRespected},
				{"PERF2_Retry_ModeOff_SingleAttempt", 0, testRetry_ModeOff_SingleAttempt},
				{"PERF2_Retry_4xxNotRetried", 0, testRetry_4xxNotRetried},
				{"PERF2_Retry_RetryAfterHonoured", 0, testRetry_RetryAfterHeaderHonoured},
				{"PERF2_Retry_ReasonLabel_503", 0, testRetry_ReasonLabel_Throttle503},
				{"PERF2_Retry_AllMetricsRegistered", 0, testRetry_AllMetricsRegistered},

				// V0.6-OBS-1 admin pprof profiling endpoints — cap=0, runs on every provider.
				// These tests start a gateway with an admin listener + profiling enabled;
				// they do not interact with the S3 backend but verify the full admin stack.
				{"OBS1_AllPprofEndpoints200", 0, testOBS1_AllEndpointsReturn200},
				{"OBS1_NoToken401", 0, testOBS1_NoTokenReturns401},
				{"OBS1_WrongToken401", 0, testOBS1_WrongTokenReturns401},
				{"OBS1_InvalidSeconds400", 0, testOBS1_InvalidSecondsReturns400},
				{"OBS1_DataPlaneNoPprofRoutes", 0, testOBS1_DataPlaneHasNoPprofRoutes},
				{"OBS1_MetricEmitted", 0, testOBS1_MetricEmitted},

				// V1.0-SEC-H03 KDF iteration conformance.
				{"KDF_Default600k_RoundTrip", 0, testKDF_Default600k_RoundTrip},
				{"KDF_LegacyRead_100k", 0, testKDF_LegacyRead_100k},
				{"KDF_CrossIteration_100k_to_600k", 0, testKDF_CrossIteration_100k_to_600k},
				{"KDF_MetadataPresent", 0, testKDF_MetadataPresent},
				{"KDF_Chunked_600k_RoundTrip", 0, testKDF_Chunked_600k_RoundTrip},
				{"KDF_Chunked_LegacyRead", 0, testKDF_Chunked_LegacyRead},

				// V1.0-CRYPTO-1 argon2id KDF conformance.
				{"KDF_Argon2id_RoundTrip", 0, testKDF_Argon2id_RoundTrip},
				{"KDF_Argon2id_LegacyRead", 0, testKDF_Argon2id_LegacyRead},
				{"KDF_Argon2id_Chunked_RoundTrip", 0, testKDF_Argon2id_Chunked_RoundTrip},

				// V1.0-CRYPTO-4 argon2id KDF for encrypted MPU conformance.
				{"KDF_Argon2id_EncryptedMPU_RoundTrip", provider.CapEncryptedMPU, testKDF_Argon2id_EncryptedMPU_RoundTrip},

				// V1.0-AUTH-1 — Gateway-managed authentication. Runs on every provider.
				{"Auth_V4_PutGetDelete", 0, testAuth_V4_PutGetDelete},
				{"Auth_Unauthenticated_Rejected", 0, testAuth_Unauthenticated_Rejected},
				{"Auth_WrongSecret_Rejected", 0, testAuth_WrongSecret_Rejected},
				{"Auth_PresignedURL_Valid", 0, testAuth_PresignedURL_Valid},
				{"Auth_PresignedURL_Expired", 0, testAuth_PresignedURL_Expired},
				{"Auth_MultiCredential", 0, testAuth_MultiCredential},
				{"Auth_ProxiedBucketFilter", 0, testAuth_ProxiedBucketFilter},

				// V1.0-COMPAT-1 SDK/Tool compatibility smoke tests
				{"Compat_AWSGoV2", provider.CapSDKAWSGoV2, testCompatSmoke_AWSGoV2},
				{"Compat_Boto3", provider.CapSDKBoto3, testCompatSmoke_Boto3},
				{"Compat_AWSCLI", provider.CapCLIAWSCLI, testCompatSmoke_AWSCLI},
				{"Compat_S5cmd", provider.CapCLIS5cmd, testCompatSmoke_S5cmd},
				{"Compat_Rclone", provider.CapCLIRclone, testCompatSmoke_Rclone},
				{"Compat_Rclone_SyncCheck_SizeCache", provider.CapCLIRclone | provider.CapSizeTranslation, testRcloneSyncCheck_SizeCache},
				{"Compat_Rclone_SyncCheck_FallbackHead", provider.CapCLIRclone | provider.CapSizeTranslation, testRcloneSyncCheck_FallbackHead},
				{"Compat_MinIOPy", provider.CapSDKMinIOPy, testCompatSmoke_MinIOPy},

				// V1.0-S3-2 S3 API feature parity
				{"S3Compat_DeleteBucket", 0, testS3Compat_DeleteBucket},
				{"S3Compat_ListBuckets", 0, testS3Compat_ListBuckets},
				{"S3Compat_GetBucketLocation", 0, testS3Compat_GetBucketLocation},
				{"S3Compat_GetBucketVersioning", provider.CapVersioning, testS3Compat_GetBucketVersioning},
				{"S3Compat_PutGetBucketVersioning", provider.CapVersioning, testS3Compat_PutGetBucketVersioning},
				{"S3Compat_ListMultipartUploads", provider.CapMultipartUpload, testS3Compat_ListMultipartUploads},
				{"S3Compat_GetPutDeleteObjectTagging", provider.CapObjectTagging, testS3Compat_GetPutDeleteObjectTagging},
				{"S3Compat_GetBucketACL", provider.CapBucketACL, testS3Compat_GetBucketACL},
				{"S3Compat_PutBucketACL", provider.CapBucketACL, testS3Compat_PutBucketACL},
				{"S3Compat_GetObjectACL", provider.CapObjectACL, testS3Compat_GetObjectACL},
				{"S3Compat_PutObjectACL", provider.CapObjectACL, testS3Compat_PutObjectACL},
				{"S3Compat_GetPutDeleteBucketPolicy", provider.CapBucketPolicy, testS3Compat_GetPutDeleteBucketPolicy},
				{"S3Compat_GetPutDeleteBucketCors", provider.CapBucketCors, testS3Compat_GetPutDeleteBucketCors},
				{"S3Compat_GetPutDeleteBucketLifecycle", provider.CapBucketLifecycle, testS3Compat_GetPutDeleteBucketLifecycle},
				{"S3Compat_CORSPreflight_OPTIONS", 0, testS3Compat_CORSPreflight_OPTIONS},
				{"S3Compat_GetPutDeleteBucketEncryption", provider.CapBucketEncryption, testS3Compat_GetPutDeleteBucketEncryption},
				{"S3Compat_SelectObjectContent_501", 0, testS3Compat_SelectObjectContent_501},
			}

			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					if tc.cap != 0 && p.Capabilities()&tc.cap == 0 {
						t.Skipf("%s does not advertise capability %s",
							p.Name(), tc.cap)
					}
					tc.fn(t, inst)
				})
			}
		})
	}
}
