//go:build !fips

package config

// isFIPS returns false when the binary is built without -tags=fips.
func isFIPS() bool { return false }
