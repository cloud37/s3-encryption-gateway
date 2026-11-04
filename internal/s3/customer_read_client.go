package s3

import (
	"context"
	"fmt"
	"io"
)

type customerReadClient struct {
	Client
	advanced    AdvancedObjectClient
	bucket, key string
	customer    *SSECustomerKey
}

// WithSSECustomerReadClient returns a request-local exact-target decorator.
// Caller owns customer and must Close it after all synchronous serving ends.
// The decorator must not be stored beyond that request; closing customer removes
// its material even if an accidental decorator reference survives cleanup.
func WithSSECustomerReadClient(client Client, bucket, key string, customer *SSECustomerKey) (Client, error) {
	if nilObjectInput(client) || customer == nil {
		return nil, fmt.Errorf("customer read client requires client and key")
	}
	advanced, ok := client.(AdvancedObjectClient)
	if !ok {
		return nil, fmt.Errorf("customer read client: %w", ErrNotImplemented)
	}
	if _, _, err := customerWireKey(customer); err != nil {
		return nil, err
	}
	return &customerReadClient{Client: client, advanced: advanced, bucket: bucket, key: key, customer: customer}, nil
}

func (c *customerReadClient) GetObject(ctx context.Context, bucket, key string, versionID, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if nilObjectInput(ctx) {
		return nil, nil, fmt.Errorf("object read requires context")
	}
	if bucket == c.bucket && key == c.key {
		return c.advanced.GetObjectWithOptions(ctx, bucket, key, versionID, rangeHeader, ObjectReadOptions{Customer: c.customer})
	}
	return c.Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}

func (c *customerReadClient) GetObjectIfMatch(ctx context.Context, bucket, key string, versionID, rangeHeader *string, ifMatch string, options ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	if nilObjectInput(ctx) || ifMatch == "" {
		return nil, nil, fmt.Errorf("conditional object read requires context and ETag")
	}
	if options.Customer != nil {
		return nil, nil, fmt.Errorf("customer read client owns customer options")
	}
	conditional, ok := c.Client.(ConditionalObjectReader)
	if !ok || nilObjectInput(conditional) {
		return nil, nil, fmt.Errorf("conditional object read: %w", ErrNotImplemented)
	}
	if bucket == c.bucket && key == c.key {
		options.Customer = c.customer
	}
	return conditional.GetObjectIfMatch(ctx, bucket, key, versionID, rangeHeader, ifMatch, options)
}

func (c *customerReadClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if nilObjectInput(ctx) {
		return nil, fmt.Errorf("object read requires context")
	}
	if bucket == c.bucket && key == c.key {
		return c.advanced.HeadObjectWithOptions(ctx, bucket, key, versionID, ObjectReadOptions{Customer: c.customer})
	}
	return c.Client.HeadObject(ctx, bucket, key, versionID)
}
