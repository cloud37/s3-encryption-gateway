package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/redis/go-redis/v9"
)

var (
	ErrCORSNotFound    = errors.New("bucket CORS configuration not found")
	ErrCORSUnavailable = errors.New("bucket CORS configuration store unavailable")
)

// CORSStore is the durable gateway-owned policy store. The owner of the shared
// Valkey client is responsible for closing it.
type CORSStore interface {
	Get(ctx context.Context, bucket string) (*CORSConfiguration, error)
	Put(ctx context.Context, bucket string, value *CORSConfiguration) error
	Delete(ctx context.Context, bucket string) error
	HealthCheck(ctx context.Context) error
}

type valkeyCORSStore struct{ client redis.UniversalClient }

func NewValkeyCORSStore(client redis.UniversalClient) CORSStore {
	if client != nil {
		value := reflect.ValueOf(client)
		if (value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface || value.Kind() == reflect.Map || value.Kind() == reflect.Slice || value.Kind() == reflect.Func) && value.IsNil() {
			client = nil
		}
	}
	return &valkeyCORSStore{client: client}
}

func corsKey(bucket string) string { return "bucketcors:v1:" + bucket }

func (s *valkeyCORSStore) Get(ctx context.Context, bucket string) (*CORSConfiguration, error) {
	if err := validateCORSStoreArgs(ctx, bucket); err != nil {
		return nil, err
	}
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("%w: nil Valkey client", ErrCORSUnavailable)
	}
	wire, err := s.client.Get(ctx, corsKey(bucket)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCORSNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: get policy: %v", ErrCORSUnavailable, err)
	}
	if len(wire) > maxCORSXMLBytes {
		return nil, fmt.Errorf("%w: policy record exceeds 64 KiB", ErrCORSUnavailable)
	}
	cfg, err := parseCORSXML([]byte(wire))
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt policy record: %v", ErrCORSUnavailable, err)
	}
	return cfg, nil
}

func (s *valkeyCORSStore) Put(ctx context.Context, bucket string, value *CORSConfiguration) error {
	if err := validateCORSStoreArgs(ctx, bucket); err != nil {
		return err
	}
	if s == nil || s.client == nil {
		return fmt.Errorf("%w: nil Valkey client", ErrCORSUnavailable)
	}
	wire, err := marshalCORSXML(value)
	if err != nil {
		return fmt.Errorf("encode bucket CORS: %w", err)
	}
	if err := s.client.Set(ctx, corsKey(bucket), wire, 0).Err(); err != nil {
		return fmt.Errorf("%w: set policy: %v", ErrCORSUnavailable, err)
	}
	return nil
}

func (s *valkeyCORSStore) Delete(ctx context.Context, bucket string) error {
	if err := validateCORSStoreArgs(ctx, bucket); err != nil {
		return err
	}
	if s == nil || s.client == nil {
		return fmt.Errorf("%w: nil Valkey client", ErrCORSUnavailable)
	}
	if err := s.client.Del(ctx, corsKey(bucket)).Err(); err != nil {
		return fmt.Errorf("%w: delete policy: %v", ErrCORSUnavailable, err)
	}
	return nil
}

func (s *valkeyCORSStore) HealthCheck(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrCORSUnavailable)
	}
	if s == nil || s.client == nil {
		return fmt.Errorf("%w: nil Valkey client", ErrCORSUnavailable)
	}
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("%w: ping: %v", ErrCORSUnavailable, err)
	}
	return nil
}

func validateCORSStoreArgs(ctx context.Context, bucket string) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrCORSUnavailable)
	}
	if err := validateCORSBucket(bucket); err != nil {
		return fmt.Errorf("%w: invalid bucket", ErrCORSUnavailable)
	}
	return nil
}

func validateCORSBucket(bucket string) error {
	if len(bucket) < 3 || len(bucket) > 63 || strings.Contains(bucket, "..") || strings.Contains(bucket, ".-") || strings.Contains(bucket, "-.") {
		return fmt.Errorf("invalid bucket name")
	}
	if bucket[0] == '.' || bucket[0] == '-' || bucket[len(bucket)-1] == '.' || bucket[len(bucket)-1] == '-' {
		return fmt.Errorf("invalid bucket name")
	}
	for _, c := range bucket {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return fmt.Errorf("invalid bucket name")
	}
	if net.ParseIP(bucket) != nil {
		return fmt.Errorf("invalid bucket name")
	}
	if pieces := strings.Split(bucket, "."); len(pieces) == 4 {
		allNumeric := true
		for _, piece := range pieces {
			if piece == "" {
				allNumeric = false
				break
			}
			for _, c := range piece {
				if c < '0' || c > '9' {
					allNumeric = false
					break
				}
			}
		}
		if allNumeric {
			return fmt.Errorf("invalid bucket name")
		}
	}
	return nil
}
