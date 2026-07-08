package sizecache

import (
	"context"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// ValkeySizeCache implements SizeCache backed by a Valkey (Redis-compatible)
// hash per bucket. Key schema: "plainsize:<bucket>" → hash of <key> → "<size>".
type ValkeySizeCache struct {
	client redis.UniversalClient
}

// NewValkeySizeCache creates a new ValkeySizeCache using the provided client.
// The client is not closed by Close if it was created externally.
func NewValkeySizeCache(client redis.UniversalClient) *ValkeySizeCache {
	return &ValkeySizeCache{client: client}
}

func bucketKey(bucket string) string {
	return "plainsize:" + bucket
}

func (c *ValkeySizeCache) Set(ctx context.Context, bucket, key string, size int64) error {
	return c.client.HSet(ctx, bucketKey(bucket), key, strconv.FormatInt(size, 10)).Err()
}

func (c *ValkeySizeCache) SetBatch(ctx context.Context, bucket string, sizes map[string]int64) error {
	if len(sizes) == 0 {
		return nil
	}
	args := make([]interface{}, 0, len(sizes)*2)
	for k, v := range sizes {
		args = append(args, k, strconv.FormatInt(v, 10))
	}
	return c.client.HSet(ctx, bucketKey(bucket), args...).Err()
}

func (c *ValkeySizeCache) GetBatch(ctx context.Context, bucket string, keys []string) (map[string]int64, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := c.client.HMGet(ctx, bucketKey(bucket), keys...).Result()
	if err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(keys))
	for i, v := range vals {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			if n, parseErr := strconv.ParseInt(s, 10, 64); parseErr == nil && n > 0 {
				result[keys[i]] = n
			}
		}
	}
	return result, nil
}

func (c *ValkeySizeCache) Delete(ctx context.Context, bucket, key string) error {
	return c.client.HDel(ctx, bucketKey(bucket), key).Err()
}

func (c *ValkeySizeCache) DeleteBatch(ctx context.Context, bucket string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.client.HDel(ctx, bucketKey(bucket), keys...).Err()
}

func (c *ValkeySizeCache) Close() error {
	return c.client.Close()
}
