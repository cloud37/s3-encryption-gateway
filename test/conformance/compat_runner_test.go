package conformance

import (
	"fmt"
	"strings"
	"testing"
)

func TestAWSCLIRunners_PinCRC64NVMEVersion(t *testing.T) {
	for _, runner := range []sdkToolRunner{&awscliRunner{}, &awscliCopyMetadataRunner{}, &awscliListBucketsRunner{}} {
		t.Run(runner.Name(), func(t *testing.T) {
			if runner.Image() != awsCLIImage || !strings.HasPrefix(runner.Image(), "amazon/aws-cli:") {
				t.Fatalf("image = %q, want shared explicit AWS CLI image %q", runner.Image(), awsCLIImage)
			}
			version := strings.TrimPrefix(runner.Image(), "amazon/aws-cli:")
			var major, minor, patch int
			if _, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); err != nil {
				t.Fatalf("image version %q is not semantic: %v", version, err)
			}
			if major < 2 || (major == 2 && (minor < 34 || (minor == 34 && patch < 32))) {
				t.Fatalf("AWS CLI version %q is below 2.34.32", version)
			}
		})
	}
	if script := (&awscliRunner{}).Script(sdkTestEnv{}); strings.Contains(script, "--checksum-algorithm") || strings.Contains(script, "WHEN_REQUIRED") {
		t.Fatalf("AWS CLI script overrides default checksum behavior: %s", script)
	}
	if script := (&awscliRunner{}).Script(sdkTestEnv{}); strings.Contains(script, "diff ") {
		t.Fatalf("AWS CLI script relies on unavailable diff command: %s", script)
	}
	if script := (&awscliRunner{}).Script(sdkTestEnv{}); strings.Contains(script, "$(cat ") || !strings.Contains(script, `open("/tmp/testfile", "rb")`) || !strings.Contains(script, `open("/tmp/testfile-dl", "rb")`) {
		t.Fatalf("AWS CLI script does not use a byte-preserving download comparison: %s", script)
	}
}

func TestAWSCLIListBucketsRunner_Contract(t *testing.T) {
	runner := &awscliListBucketsRunner{}
	if runner.Image() != awsCLIImage {
		t.Fatalf("image=%q want=%q", runner.Image(), awsCLIImage)
	}
	script := runner.Script(sdkTestEnv{Bucket: "fixture-bucket"})
	for _, want := range []string{`aws s3 ls --endpoint-url "$GATEWAY_ENDPOINT"`, "fixture-bucket", "awscli-list-buckets:OK"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q: %s", want, script)
		}
	}
	if strings.Contains(script, "s3://") {
		t.Fatalf("root list command must not target a bucket: %s", script)
	}
	if runner.AssertOutput(1, "awscli-list-buckets:OK", "") == nil || runner.AssertOutput(0, "", "") == nil || runner.AssertOutput(0, "awscli-list-buckets:OK", "") != nil {
		t.Fatal("runner output contract failed")
	}
}

// TestRunToolContainer_ExitNonZero_ReturnsError asserts that every
// container-based runner's AssertOutput returns a non-nil error when the
// container exits with a non-zero code. This verifies the error-detection
// contract of the sdkToolRunner interface without requiring Docker.
func TestRunToolContainer_ExitNonZero_ReturnsError(t *testing.T) {
	runners := []sdkToolRunner{
		&boto3Runner{},
		&awscliRunner{},
		&awscliListBucketsRunner{},
		&s5cmdRunner{},
		&rcloneRunner{},
		&minioPyRunner{},
		&resticRoundTripRunner{},
		&resticBackupGatewayRestoreDirectRunner{},
	}
	for _, r := range runners {
		r := r
		t.Run(r.Name(), func(t *testing.T) {
			err := r.AssertOutput(1, "some output", "")
			if err == nil {
				t.Errorf("%s: AssertOutput(1, ...) returned nil, want error", r.Name())
			}
		})
	}
}

// TestRunToolContainer_MissingMarker_ReturnsError asserts that every
// container-based runner's AssertOutput returns a non-nil error when the
// expected OK marker string is absent from stdout, even on a zero exit code.
// This catches regression where a tool exits 0 but the actual work failed
// silently.
func TestRunToolContainer_MissingMarker_ReturnsError(t *testing.T) {
	runners := []sdkToolRunner{
		&boto3Runner{},
		&awscliRunner{},
		&awscliListBucketsRunner{},
		&s5cmdRunner{},
		&rcloneRunner{},
		&minioPyRunner{},
		&resticRoundTripRunner{},
		&resticBackupGatewayRestoreDirectRunner{},
	}
	for _, r := range runners {
		r := r
		t.Run(r.Name(), func(t *testing.T) {
			err := r.AssertOutput(0, "output without the expected OK marker", "")
			if err == nil {
				t.Errorf("%s: AssertOutput(0, 'no marker', ...) returned nil, want error",
					r.Name())
			}
		})
	}
}

// TestRunToolContainer_SuccessMarker_ReturnsNil asserts that every
// container-based runner's AssertOutput returns nil when the expected OK
// marker is present and the exit code is zero.
func TestRunToolContainer_SuccessMarker_ReturnsNil(t *testing.T) {
	cases := []struct {
		runner sdkToolRunner
		marker string
	}{
		{&boto3Runner{}, "boto3:OK"},
		{&awscliRunner{}, "awscli:OK"},
		{&s5cmdRunner{}, "s5cmd:OK"},
		{&rcloneRunner{}, "rclone:OK"},
		{&minioPyRunner{}, "minio-py:OK"},
		{&resticRoundTripRunner{}, "restic:roundtrip:OK"},
		{&resticBackupGatewayRestoreDirectRunner{}, "restic:hybrid:OK"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.runner.Name(), func(t *testing.T) {
			err := tc.runner.AssertOutput(0, tc.marker, "")
			if err != nil {
				t.Errorf("%s: AssertOutput(0, %q, ...) = %v, want nil",
					tc.runner.Name(), tc.marker, err)
			}
		})
	}
}
