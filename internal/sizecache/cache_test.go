package sizecache

import (
	"context"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestValkeyCache(t *testing.T) (*ValkeySizeCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return NewValkeySizeCache(client), mr
}

func TestValkeySizeCache_Set_Get_RoundTrip(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	err := cache.Set(ctx, "bucket1", "key1", 12345)
	require.NoError(t, err)

	results, err := cache.GetBatch(ctx, "bucket1", []string{"key1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"key1": 12345}, results)
}

func TestValkeySizeCache_GetBatch_PartialHit(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	require.NoError(t, cache.Set(ctx, "bucket1", "a", 10))
	require.NoError(t, cache.Set(ctx, "bucket1", "b", 20))
	require.NoError(t, cache.Set(ctx, "bucket1", "c", 30))

	results, err := cache.GetBatch(ctx, "bucket1", []string{"a", "b", "c", "d", "e"})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"a": 10, "b": 20, "c": 30}, results)
}

func TestValkeySizeCache_GetBatch_EmptyKeys(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	results, err := cache.GetBatch(ctx, "bucket1", nil)
	require.NoError(t, err)
	assert.Nil(t, results)

	results, err = cache.GetBatch(ctx, "bucket1", []string{})
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestValkeySizeCache_Delete_Evicts(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	require.NoError(t, cache.Set(ctx, "bucket1", "key1", 12345))
	require.NoError(t, cache.Delete(ctx, "bucket1", "key1"))

	results, err := cache.GetBatch(ctx, "bucket1", []string{"key1"})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestValkeySizeCache_DeleteBatch(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	require.NoError(t, cache.Set(ctx, "bucket1", "a", 1))
	require.NoError(t, cache.Set(ctx, "bucket1", "b", 2))
	require.NoError(t, cache.Set(ctx, "bucket1", "c", 3))

	require.NoError(t, cache.DeleteBatch(ctx, "bucket1", []string{"a", "c"}))

	results, err := cache.GetBatch(ctx, "bucket1", []string{"a", "b", "c"})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"b": 2}, results)
}

func TestValkeySizeCache_SetBatch(t *testing.T) {
	cache, _ := newTestValkeyCache(t)
	ctx := context.Background()

	err := cache.SetBatch(ctx, "bucket1", map[string]int64{
		"x": 100,
		"y": 200,
		"z": 300,
	})
	require.NoError(t, err)

	results, err := cache.GetBatch(ctx, "bucket1", []string{"x", "y", "z", "w"})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"x": 100, "y": 200, "z": 300}, results)
}

func TestNoopSizeCache_AllOpsNoError(t *testing.T) {
	cache := &NoopSizeCache{}
	ctx := context.Background()

	assert.NoError(t, cache.Set(ctx, "b", "k", 1))
	assert.NoError(t, cache.SetBatch(ctx, "b", map[string]int64{"k": 1}))
	results, err := cache.GetBatch(ctx, "b", []string{"k"})
	assert.NoError(t, err)
	assert.Nil(t, results)
	assert.NoError(t, cache.Delete(ctx, "b", "k"))
	assert.NoError(t, cache.DeleteBatch(ctx, "b", []string{"k"}))
	assert.NoError(t, cache.Close())
}

// TestValkeySizeCache_RejectsZeroSize verifies GetBatch skips zero/negative values.
func TestValkeySizeCache_RejectsZeroSize(t *testing.T) {
	cache, mr := newTestValkeyCache(t)
	ctx := context.Background()

	// Manually insert a zero-size entry into miniredis to simulate bad data.
	mr.HSet("plainsize:bucket1", "badkey", strconv.FormatInt(0, 10))

	// Also insert a valid entry.
	require.NoError(t, cache.Set(ctx, "bucket1", "goodkey", 42))

	results, err := cache.GetBatch(ctx, "bucket1", []string{"badkey", "goodkey"})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"goodkey": 42}, results)
}
