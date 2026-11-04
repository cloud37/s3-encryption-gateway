package s3

import (
	"context"
	"crypto/md5" // S3 customer-key protocol checksum, not authentication.
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"
	"strconv"
)

type ObjectPutOptions struct {
	StorageClass            string
	WebsiteRedirectLocation string
	SSE                     *SSEOptions
}

type SSEOptions struct {
	Algorithm, KMSKeyID, KMSContext string
	BucketKeyEnabled                *bool
	Customer                        *SSECustomerKey
}

// SSECustomerKey is request-owned. Close only after synchronous I/O finishes;
// it wipes the caller's mutable backing bytes and releases temporary references.
type SSECustomerKey struct {
	Key []byte
	MD5 string
}

func (k *SSECustomerKey) Close() {
	if k == nil {
		return
	}
	clear(k.Key)
	k.Key = nil
	k.MD5 = ""
}

type ObjectReadOptions struct{ Customer *SSECustomerKey }
type PutObjectResult struct {
	ETag, VersionID string
	Headers         map[string]string
}

// AdvancedObjectClient is additive to Client. Callers own inputs; synchronous
// methods do not retain bodies, metadata, options or customer keys. Nil context
// or body is invalid. Returned read bodies remain caller-owned until Close.
type AdvancedObjectClient interface {
	Client
	PutObjectWithOptions(ctx context.Context, bucket, key string, body io.Reader, metadata map[string]string, length *int64, tags string, lock *ObjectLockInput, acl, grantFullControl, grantRead, grantReadACP, grantWriteACP string, options ObjectPutOptions) (PutObjectResult, error)
	GetObjectWithOptions(ctx context.Context, bucket, key string, versionID, rangeHeader *string, options ObjectReadOptions) (io.ReadCloser, map[string]string, error)
	HeadObjectWithOptions(ctx context.Context, bucket, key string, versionID *string, options ObjectReadOptions) (map[string]string, error)
}

// ConditionalObjectReader is an optional capability: implementations must send
// the non-empty opaque backend ETag as If-Match, or fail without a read. It is
// separate from AdvancedObjectClient so older implementations cannot silently
// ignore a newly added condition. Returned bodies remain caller-owned.
type ConditionalObjectReader interface {
	GetObjectIfMatch(ctx context.Context, bucket, key string, versionID, rangeHeader *string, ifMatch string, options ObjectReadOptions) (io.ReadCloser, map[string]string, error)
}

// nilObjectInput handles typed-nil interfaces at these public boundaries.
func nilObjectInput(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func customerWireKey(customer *SSECustomerKey) (string, string, error) {
	if customer == nil {
		return "", "", nil
	}
	if len(customer.Key) != 32 || customer.MD5 == "" {
		return "", "", fmt.Errorf("invalid SSE customer key")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(customer.MD5)
	want := md5.Sum(customer.Key)
	if err != nil || len(decoded) != md5.Size || base64.StdEncoding.EncodeToString(decoded) != customer.MD5 || subtle.ConstantTimeCompare(decoded, want[:]) != 1 {
		return "", "", fmt.Errorf("invalid SSE customer key checksum")
	}
	return base64.StdEncoding.EncodeToString(customer.Key), customer.MD5, nil
}

// Only non-secret SDK response fields enter this closed projection. KMS context
// and customer key bytes/base64 strings are never response metadata.
func addObjectOptionHeaders(out map[string]string, algorithm, kmsID string, bucketKey *bool, customerAlgorithm, customerMD5, expiration, storage, website string) {
	for name, value := range map[string]string{
		"x-amz-server-side-encryption":                    algorithm,
		"x-amz-server-side-encryption-aws-kms-key-id":     kmsID,
		"x-amz-server-side-encryption-customer-algorithm": customerAlgorithm,
		"x-amz-server-side-encryption-customer-key-MD5":   customerMD5,
		"x-amz-expiration":                                expiration, "x-amz-storage-class": storage,
		"x-amz-website-redirect-location": website,
	} {
		if value != "" {
			out[name] = value
		}
	}
	if bucketKey != nil {
		out["x-amz-server-side-encryption-bucket-key-enabled"] = strconv.FormatBool(*bucketKey)
	}
}

func advancedAdapterClient(inner Client, options ObjectPutOptions) (AdvancedObjectClient, error) {
	if options.SSE != nil || (options.StorageClass != "" && options.StorageClass != "STANDARD") || options.WebsiteRedirectLocation != "" {
		return nil, fmt.Errorf("advanced object options: %w", ErrNotImplemented)
	}
	advanced, ok := inner.(AdvancedObjectClient)
	if !ok || nilObjectInput(advanced) {
		return nil, fmt.Errorf("advanced object client: %w", ErrNotImplemented)
	}
	return advanced, nil
}
