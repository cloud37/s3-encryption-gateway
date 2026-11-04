//go:build conformance

package conformance

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func TestGH353ProtectedFixtureCompactProfile(t *testing.T) {
	for _, candidate := range provider.GH353FeedbackProviders() {
		name := candidate.Name()
		if crypto.GetProviderProfile(name).CompactionStrategy != "none" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			requests := make(chan http.Header, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				requests <- r.Header.Clone()
				w.Header().Set("ETag", `"fixture"`)
			}))
			defer backend.Close()
			inst := provider.Instance{ProviderName: name, Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
			original := inst
			var configured config.BackendConfig
			gw := postProtectedGateway(t, inst, postCredential("", nil), harness.WithChunking(true), harness.WithMetadataEncryptionKey(bytes.Repeat([]byte{0x42}, 32)), harness.WithConfigMutator(func(cfg *config.Config) {
				configured = cfg.Backend
			}))
			if !reflect.DeepEqual(inst, original) || configured.Provider != inst.ProviderName || configured.Endpoint != inst.Endpoint || configured.Region != inst.Region || configured.AccessKey != inst.AccessKey || configured.SecretKey != inst.SecretKey || configured.MetadataProfile != "compact" {
				t.Fatal("protected fixture changed provider identity or failed to configure compact")
			}
			profile, err := crypto.ResolveMetadataProfile(configured.Provider, configured.MetadataProfile)
			if err != nil || profile.UserMetadataLimit != 2048 || profile.TotalHeaderLimit != 8192 || profile.CompactionStrategy != "base64url" || crypto.GetProviderProfile(name).CompactionStrategy != "none" {
				t.Fatal("protected fixture profile or legacy default changed")
			}
			fields := map[string]string{"Content-Type": "application/octet-stream", "Content-Encoding": "identity", "Content-Disposition": "attachment", "Cache-Control": "private", "Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT", "x-amz-meta-owner": "protected-post", "x-amz-meta-purpose": "round-trip"}
			credential := postCredential("", nil)
			req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, "fixture-key", credential, postFormCase{fields: fields, file: bytes.Repeat([]byte("protected-post-record/"), 128)})
			resp, body := postHTTP(t, gw, credential, req)
			if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
				t.Fatalf("protected fixture status=%d code=%s", resp.StatusCode, postSafeErrorCode(body))
			}
			var headers http.Header
			select {
			case headers = <-requests:
			default:
				t.Fatal("protected fixture did not write to backend")
			}
			if headers.Get(crypto.MetaEncryptedMetadataCompact) == "" || headers.Get(crypto.MetaEncryptedMetadata) != "" {
				t.Fatal("actual gateway engine did not emit compact sealed metadata")
			}
			envelope := make(map[string]string)
			for key, values := range headers {
				if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") && len(values) == 1 {
					envelope[key] = values[0]
				}
			}
			if err := profile.ValidateMetadataSize(envelope); err != nil {
				t.Fatalf("actual protected metadata envelope exceeds budget: %v", err)
			}
		})
	}
}
