package crypto

import (
	"runtime"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"golang.org/x/sys/cpu"
)

// HasAESHardwareSupport checks if the CPU supports AES hardware acceleration.
// This uses CPU feature detection available in golang.org/x/sys/cpu.
func HasAESHardwareSupport() bool {
	switch runtime.GOARCH {
	case "amd64", "386":
		return cpu.X86.HasAES
	case "arm64":
		return cpu.ARM64.HasAES
	case "s390x":
		return cpu.S390X.HasAES
	default:
		return false
	}
}

// IsHardwareAccelerationEnabled checks if hardware acceleration is supported AND enabled in config.
func IsHardwareAccelerationEnabled(cfg config.HardwareConfig) bool {
	if !HasAESHardwareSupport() {
		return false
	}

	switch runtime.GOARCH {
	case "amd64", "386":
		return cfg.EnableAESNI
	case "arm64":
		return cfg.EnableARMv8AES
	default:
		// If supported (e.g. s390x) but no specific flag, assume enabled
		return true
	}
}

// GetHardwareAccelerationInfo returns information about hardware acceleration support.
func GetHardwareAccelerationInfo(cfg *config.HardwareConfig) map[string]interface{} {
	info := map[string]interface{}{
		"aes_hardware_support": HasAESHardwareSupport(),
		"architecture":         runtime.GOARCH,
		"goos":                 runtime.GOOS,
		"go_version":           runtime.Version(),
	}

	if cfg != nil {
		info["aes_ni_enabled"] = cfg.EnableAESNI
		info["armv8_aes_enabled"] = cfg.EnableARMv8AES
		info["hardware_acceleration_active"] = IsHardwareAccelerationEnabled(*cfg)
	}

	return info
}
