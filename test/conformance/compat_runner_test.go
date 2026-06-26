package conformance

import (
	"testing"
)

// TestRunToolContainer_ExitNonZero_ReturnsError asserts that every
// container-based runner's AssertOutput returns a non-nil error when the
// container exits with a non-zero code. This verifies the error-detection
// contract of the sdkToolRunner interface without requiring Docker.
func TestRunToolContainer_ExitNonZero_ReturnsError(t *testing.T) {
	runners := []sdkToolRunner{
		&boto3Runner{},
		&awscliRunner{},
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
