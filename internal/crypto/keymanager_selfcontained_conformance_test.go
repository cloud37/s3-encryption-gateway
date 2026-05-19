package crypto

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESKEKManager_Conformance(t *testing.T) {
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		t.Helper()
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)
		km, err := NewAESKEKManager(map[int][]byte{1: key}, 1)
		require.NoError(t, err)
		return km
	})
}

func TestAESKEKManager_Rotation_Conformance(t *testing.T) {
	ConformanceSuite_Rotation(t, newAESFactory(t), func(t *testing.T, km KeyManager, version int) error {
		t.Helper()
		material := make([]byte, 32)
		for i := range material {
			material[i] = byte(version*37 + i + 1)
		}
		if aekm, ok := km.(*AESKEKManager); ok {
			return aekm.AddVersion(context.Background(), version, material)
		}
		return ErrRotationNotSupported
	})
}
