package audit

import (
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// ObjectClass represents the classification of an S3 object for audit purposes.
type ObjectClass int

const (
	ClassModern      ObjectClass = iota // No migration needed
	ClassA_XOR                          // SEC-2: XOR IV derivation
	ClassB_NoAAD                        // SEC-4: no-AAD legacy
	ClassC_Fallback_XOR                 // SEC-27 + SEC-2: v1 fallback + XOR IV
	ClassC_Fallback_HKDF                // SEC-27: v1 fallback, HKDF IV already
	ClassD_LegacyKDF                    // SEC-H03: legacy PBKDF2 100k, no KDF params metadata
	ClassPlaintext                      // Not encrypted; skip
	ClassUnknown                        // Cannot determine; log and skip
)

// ClassToString returns a human-readable name for an ObjectClass.
func ClassToString(c ObjectClass) string {
	switch c {
	case ClassModern:
		return "modern"
	case ClassA_XOR:
		return "class_a_xor"
	case ClassB_NoAAD:
		return "class_b_no_aad"
	case ClassC_Fallback_XOR:
		return "class_c_fallback_xor"
	case ClassC_Fallback_HKDF:
		return "class_c_fallback_hkdf"
	case ClassD_LegacyKDF:
		return "class_d_legacy_kdf"
	case ClassPlaintext:
		return "plaintext"
	case ClassUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// ClassifyObject inspects object metadata and returns its classification.
//
// Classification rules (from V1.0-MAINT-1 plan §2.3):
//
//	┌──────────────────────────────────────────────────────────┐
//	│           Encrypted Object (x-amz-meta-encrypted=true)  │
//	└───────────────────────────┬──────────────────────────────┘
//	                            │
//	          ┌─────────────────┴──────────────────┐
//	          │                                │
//	   x-amz-meta-                      x-amz-meta-
//	encryption-fallback             encryption-fallback
//	     absent                         = "true"
//	          │                                │
//	┌─────────┴──────────┐      ┌─────────────┴───────────┐
//	│                    │      │                         │
//	x-amz-meta-      x-amz-meta-  fallback-version    fallback-version
//	enc-iv-deriv=    enc-legacy-no-aad  absent / "1"       = "2"
//	"hkdf-sha256"    = "true"        │                    already
//	     │              │       ┌────┴────┐            migrated
//	 MODERN          CLASS B    │         │            (no action)
//	                 SEC-4  enc-iv-deriv=    enc-iv-deriv=
//	                        "hkdf-sha256"     absent/""
//	                             │              │
//	                        C_HKDF         C_XOR (also
//	                      (half-migrated)   CLASS A)
func ClassifyObject(meta map[string]string) ObjectClass {
	if meta == nil {
		return ClassPlaintext
	}

	// Check for encrypted flag (supports both full and compact form)
	isEncrypted := meta[crypto.MetaEncrypted] == "true" || meta["x-amz-meta-e"] == "true"
	if !isEncrypted {
		return ClassPlaintext
	}

	isFallback := meta[crypto.MetaFallbackMode] == "true"
	fallbackVer := meta[crypto.MetaFallbackVersion] // "" or "1" = legacy; "2" = new
	ivDeriv := meta[crypto.MetaIVDerivation]        // "" = XOR; "hkdf-sha256" = new
	legacyNoAAD := meta[crypto.MetaLegacyNoAAD] == "true"
	isChunked := meta[crypto.MetaChunkedFormat] == "true"

	if isFallback {
		if fallbackVer == "2" {
			// fallback v2, check other flags below (fall through to modern check)
		} else {
			// fallback v1 (absent or "1")
			if ivDeriv == "" {
				return ClassC_Fallback_XOR
			}
			return ClassC_Fallback_HKDF
		}
	}

	if legacyNoAAD {
		return ClassB_NoAAD
	}

	if isChunked && ivDeriv == "" {
		return ClassA_XOR
	}

	// Class D — legacy KDF: MetaKDFParams is absent, meaning the object was
	// encrypted before KDF params were recorded (legacy 100k PBKDF2, no
	// explicit params stored).
	if meta[crypto.MetaKDFParams] == "" {
		return ClassD_LegacyKDF
	}

	return ClassModern
}

// NeedsMigration reports whether an object of the given class needed migration.
// Retained for compatibility; audit tools may use this to flag objects.
func NeedsMigration(c ObjectClass) bool {
	switch c {
	case ClassA_XOR, ClassB_NoAAD, ClassC_Fallback_XOR, ClassC_Fallback_HKDF, ClassD_LegacyKDF:
		return true
	default:
		return false
	}
}
