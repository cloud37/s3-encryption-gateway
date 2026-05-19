//go:build fips

package config

// isFIPS returns true when the binary is built with -tags=fips.
func isFIPS() bool { return true }
