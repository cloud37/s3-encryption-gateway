package crypto

import (
	"runtime"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
)

func TestHasAESHardwareSupport(t *testing.T) {
	// This test just verifies the function works and returns a boolean
	// We can't easily mock cpu features, so we just ensure it doesn't panic
	_ = HasAESHardwareSupport()
}

func TestIsHardwareAccelerationEnabled(t *testing.T) {
	// Create dummy config
	cfg := config.HardwareConfig{
		EnableAESNI:    true,
		EnableARMv8AES: true,
	}

	// Result depends on hardware support, which we can't easily mock without interface.
	// But we can test logic: IsHardwareAccelerationEnabled(cfg) should match HasAESHardwareSupport()
	// when flags are true.
	expected := HasAESHardwareSupport()
	if IsHardwareAccelerationEnabled(cfg) != expected {
		t.Errorf("IsHardwareAccelerationEnabled(true) = %v, want %v (HasAESHardwareSupport)", IsHardwareAccelerationEnabled(cfg), expected)
	}

	// If we disable the flag for current arch, it should be false (if supported)
	if HasAESHardwareSupport() {
		disabledCfg := config.HardwareConfig{
			EnableAESNI:    false,
			EnableARMv8AES: false,
		}
		// Note: This assumes we are on amd64 or arm64 where flags apply
		if IsHardwareAccelerationEnabled(disabledCfg) {
			// On s390x it might still be true as we didn't add flag for it.
			// Check arch
			if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
				t.Errorf("IsHardwareAccelerationEnabled(false) = true, want false")
			}
		}
	}
}

func TestGetHardwareAccelerationInfo(t *testing.T) {
	info := GetHardwareAccelerationInfo(nil)

	// Verify required fields
	requiredFields := []string{"aes_hardware_support", "architecture", "goos", "go_version"}
	for _, field := range requiredFields {
		if _, ok := info[field]; !ok {
			t.Errorf("GetHardwareAccelerationInfo(nil) missing field: %s", field)
		}
	}

	// With config
	cfg := &config.HardwareConfig{
		EnableAESNI:    true,
		EnableARMv8AES: true,
	}
	infoWithCfg := GetHardwareAccelerationInfo(cfg)
	if _, ok := infoWithCfg["aes_ni_enabled"]; !ok {
		t.Errorf("GetHardwareAccelerationInfo(cfg) missing aes_ni_enabled")
	}
	if _, ok := infoWithCfg["hardware_acceleration_active"]; !ok {
		t.Errorf("GetHardwareAccelerationInfo(cfg) missing hardware_acceleration_active")
	}
}
