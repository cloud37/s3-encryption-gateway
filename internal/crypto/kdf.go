package crypto

import (
	"fmt"
	"strconv"
	"strings"
)

// KDFAlgorithm identifies the key derivation function.
type KDFAlgorithm string

const (
	KDFAlgPBKDF2SHA256 KDFAlgorithm = "pbkdf2-sha256"
	KDFAlgArgon2id     KDFAlgorithm = "argon2id" // non-FIPS only

	// Legacy sentinel: returned when MetaKDFParams is absent.
	// Treated as pbkdf2-sha256 with LegacyPBKDF2Iterations.
	LegacyPBKDF2Iterations  = 100000
	DefaultPBKDF2Iterations = 600000
	MinPBKDF2Iterations     = 100000
	// MaxPBKDF2Iterations is a hard upper bound used by envelope format
	// detection in PasswordKeyManager.UnwrapKey.  It prevents a mistaken
	// new-format attempt on an old-format envelope (whose first 4 bytes
	// are random salt) from hanging on a multi-billion-iteration PBKDF2
	// derivation.  2,000,000 is well above any sensible production value
	// while keeping a mistaken attempt under ~10 s even with -race.
	MaxPBKDF2Iterations        = 2000000
	MinArgon2idTime     uint32 = 1
	MaxArgon2idTime     uint32 = 10
	MinArgon2idMemory   uint32 = 1
	MaxArgon2idMemory   uint32 = 1048576
	MinArgon2idThreads  uint8  = 1
	MaxArgon2idThreads  uint8  = 255
)

// KDFLimits contains operational decrypt ceilings.
type KDFLimits struct {
	PBKDF2MaxIterations int
	Argon2idMaxTime     uint32
	Argon2idMaxMemory   uint32
	Argon2idMaxThreads  uint8
}

func DefaultKDFLimits() KDFLimits {
	return KDFLimits{PBKDF2MaxIterations: MaxPBKDF2Iterations, Argon2idMaxTime: MaxArgon2idTime, Argon2idMaxMemory: 65536, Argon2idMaxThreads: MaxArgon2idThreads}
}

type ErrInvalidKDFParams struct {
	Algorithm KDFAlgorithm
	Parameter string
	Value     uint64
	Reason    string
}

func (e *ErrInvalidKDFParams) Error() string {
	return fmt.Sprintf("invalid %s KDF parameter %s=%d: %s", e.Algorithm, e.Parameter, e.Value, e.Reason)
}

type ErrKDFCostTooHigh struct {
	Algorithm KDFAlgorithm
	Parameter string
	Requested uint64
	Maximum   uint64
}

func (e *ErrKDFCostTooHigh) Error() string {
	return fmt.Sprintf("%s KDF parameter %s=%d exceeds maximum %d", e.Algorithm, e.Parameter, e.Requested, e.Maximum)
}

func invalidKDF(alg KDFAlgorithm, parameter string, value uint64, reason string) error {
	return &ErrInvalidKDFParams{Algorithm: alg, Parameter: parameter, Value: value, Reason: reason}
}

func ValidateKDFParams(params KDFParams, limits KDFLimits) error {
	switch params.Algorithm {
	case KDFAlgPBKDF2SHA256:
		if params.Iterations < MinPBKDF2Iterations || params.Iterations > MaxPBKDF2Iterations {
			return invalidKDF(params.Algorithm, "iterations", uint64(max(params.Iterations, 0)), fmt.Sprintf("must be between %d and %d", MinPBKDF2Iterations, MaxPBKDF2Iterations))
		}
		if params.Iterations > limits.PBKDF2MaxIterations {
			return &ErrKDFCostTooHigh{Algorithm: params.Algorithm, Parameter: "iterations", Requested: uint64(params.Iterations), Maximum: uint64(limits.PBKDF2MaxIterations)}
		}
	case KDFAlgArgon2id:
		if params.Time < MinArgon2idTime || params.Time > MaxArgon2idTime {
			return invalidKDF(params.Algorithm, "time", uint64(params.Time), "must be between 1 and 10")
		}
		if params.Memory < MinArgon2idMemory || params.Memory > MaxArgon2idMemory {
			return invalidKDF(params.Algorithm, "memory", uint64(params.Memory), "must be between 1 and 1048576")
		}
		if params.Threads < MinArgon2idThreads || params.Threads > MaxArgon2idThreads {
			return invalidKDF(params.Algorithm, "threads", uint64(params.Threads), "must be between 1 and 255")
		}
		if params.Time > limits.Argon2idMaxTime {
			return &ErrKDFCostTooHigh{Algorithm: params.Algorithm, Parameter: "time", Requested: uint64(params.Time), Maximum: uint64(limits.Argon2idMaxTime)}
		}
		if params.Memory > limits.Argon2idMaxMemory {
			return &ErrKDFCostTooHigh{Algorithm: params.Algorithm, Parameter: "memory", Requested: uint64(params.Memory), Maximum: uint64(limits.Argon2idMaxMemory)}
		}
		if params.Threads > limits.Argon2idMaxThreads {
			return &ErrKDFCostTooHigh{Algorithm: params.Algorithm, Parameter: "threads", Requested: uint64(params.Threads), Maximum: uint64(limits.Argon2idMaxThreads)}
		}
	default:
		return invalidKDF(params.Algorithm, "algorithm", 0, "unsupported algorithm")
	}
	return nil
}

// KDFParams holds the parsed parameters for a KDF stored in MetaKDFParams.
type KDFParams struct {
	Algorithm KDFAlgorithm
	// PBKDF2 fields
	Iterations int
	// argon2id fields (zero when not argon2id)
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// FormatKDFParams serialises KDFParams to the MetaKDFParams wire format.
func FormatKDFParams(p KDFParams) string {
	switch p.Algorithm {
	case KDFAlgPBKDF2SHA256:
		return fmt.Sprintf("%s:%d", KDFAlgPBKDF2SHA256, p.Iterations)
	case KDFAlgArgon2id:
		return fmt.Sprintf("%s:%d:%d:%d", KDFAlgArgon2id, p.Time, p.Memory, p.Threads)
	default:
		return ""
	}
}

// ParseKDFParams parses a MetaKDFParams value.
// Returns the LegacyPBKDF2Iterations PBKDF2 params when value is empty (absent).
func ParseKDFParams(value string) (KDFParams, error) {
	if value == "" {
		return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: LegacyPBKDF2Iterations}, nil
	}

	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return KDFParams{}, invalidKDF("", "format", 0, "expected at least algorithm:parameter")
	}

	alg := KDFAlgorithm(parts[0])
	switch alg {
	case KDFAlgPBKDF2SHA256:
		if len(parts) != 2 {
			return KDFParams{}, invalidKDF(alg, "format", uint64(len(parts)), "expected 2 colon-delimited parts")
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil {
			return KDFParams{}, invalidKDF(alg, "iterations", 0, err.Error())
		}
		if iter < MinPBKDF2Iterations {
			return KDFParams{}, invalidKDF(alg, "iterations", uint64(max(iter, 0)), fmt.Sprintf("must be between %d and %d", MinPBKDF2Iterations, MaxPBKDF2Iterations))
		}
		if iter > MaxPBKDF2Iterations {
			return KDFParams{}, invalidKDF(alg, "iterations", uint64(iter), "exceeds hard maximum")
		}
		return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: iter}, nil
	case KDFAlgArgon2id:
		if len(parts) != 4 {
			return KDFParams{}, invalidKDF(alg, "format", uint64(len(parts)), "expected 4 colon-delimited parts")
		}
		time, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return KDFParams{}, invalidKDF(alg, "time", 0, err.Error())
		}
		memory, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return KDFParams{}, invalidKDF(alg, "memory", 0, err.Error())
		}
		if time < uint64(MinArgon2idTime) || time > uint64(MaxArgon2idTime) {
			return KDFParams{}, invalidKDF(alg, "time", time, "must be between 1 and 10")
		}
		if memory < uint64(MinArgon2idMemory) || memory > uint64(MaxArgon2idMemory) {
			return KDFParams{}, invalidKDF(alg, "memory", memory, "must be between 1 and 1048576")
		}
		threads, err := strconv.ParseUint(parts[3], 10, 8)
		if err != nil {
			return KDFParams{}, invalidKDF(alg, "threads", 0, err.Error())
		}
		if threads < uint64(MinArgon2idThreads) {
			return KDFParams{}, invalidKDF(alg, "threads", threads, "must be between 1 and 255")
		}
		return KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      uint32(time),
			Memory:    uint32(memory),
			Threads:   uint8(threads),
		}, nil
	default:
		return KDFParams{}, invalidKDF(alg, "algorithm", 0, "unsupported algorithm")
	}
}

// DefaultKDFParams returns the KDFParams for newly-written objects
// using the configured iteration count.
func DefaultKDFParams(pbkdf2Iterations int) KDFParams {
	if pbkdf2Iterations < MinPBKDF2Iterations {
		pbkdf2Iterations = DefaultPBKDF2Iterations
	}
	return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: pbkdf2Iterations}
}
