//go:build fips

package mpu

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestMPUPartClaim_FIPS_HMACSHA256(t *testing.T) {
	claim, err := ComputePartClaim(bytes.Repeat([]byte{7}, 32), 1, 4, bytes.NewReader([]byte("data")))
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, claim)
	engine, err := crypto.NewEngine(bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	r, _, err := engine.Encrypt(context.Background(), bytes.NewReader([]byte("fips mpu")), nil)
	require.NoError(t, err)
	_, err = io.ReadAll(r)
	require.NoError(t, err)
}
