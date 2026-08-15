package api

import (
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func TestStaticCredentialStore_Lookup_Known(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Label: "primary"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	credential, err := store.Lookup("AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if credential.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("secret = %q, want %q", credential.SecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	}
	if credential.Label != "primary" {
		t.Errorf("label = %q, want %q", credential.Label, "primary")
	}
}

func TestCredentialStore_ReplaceInvalidRetainsPreviousSnapshot(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "good", SecretKey: "secret", Buckets: []string{"tenant"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]config.GatewayCredential{{AccessKey: "bad", SecretKey: "secret", Permissions: ptrPermission("invalid")}}); err == nil {
		t.Fatal("expected invalid replacement error")
	}
	credential, err := store.Lookup("good")
	if err != nil || !credential.AllowsBucket("tenant") {
		t.Fatalf("old snapshot lost: credential=%+v error=%v", credential, err)
	}
}

func TestCredentialStore_ConcurrentLookupAndReplace(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := store.Lookup("key"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := store.Replace([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret", Buckets: []string{"tenant-*"}}}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestCredentialStore_ExplicitEmptyScopeRemainsDenyAll(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret", Buckets: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Policy.Buckets == nil || credential.AllowsBucket("any-bucket") {
		t.Fatal("explicit empty scope became unrestricted")
	}
}

func TestStaticCredentialStore_Lookup_Unknown(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "secret", Label: "primary"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	_, err = store.Lookup("UNKNOWNKEY")
	if err != ErrUnknownAccessKey {
		t.Fatalf("Lookup error = %v, want ErrUnknownAccessKey", err)
	}
}

func TestStaticCredentialStore_EmptyStore(t *testing.T) {
	_, err := NewStaticCredentialStore(nil)
	if err == nil {
		t.Fatal("expected error for empty credential list")
	}
	_, err = NewStaticCredentialStore([]config.GatewayCredential{})
	if err == nil {
		t.Fatal("expected error for empty credential list")
	}
}

func TestStaticCredentialStore_MissingAccessKey(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "", SecretKey: "secret"},
	}
	_, err := NewStaticCredentialStore(creds)
	if err == nil {
		t.Fatal("expected error for missing access key")
	}
}

func TestStaticCredentialStore_MissingSecretKey(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: ""},
	}
	_, err := NewStaticCredentialStore(creds)
	if err == nil {
		t.Fatal("expected error for missing secret key")
	}
}

func TestStaticCredentialStore_MultipleCredentials(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "key1", SecretKey: "secret1", Label: "first"},
		{AccessKey: "key2", SecretKey: "secret2", Label: "second"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	credential, err := store.Lookup("key2")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if credential.SecretKey != "secret2" {
		t.Errorf("secret = %q, want %q", credential.SecretKey, "secret2")
	}
	if credential.Label != "second" {
		t.Errorf("label = %q, want %q", credential.Label, "second")
	}
}

func ptrPermission(p config.ObjectPermission) *config.ObjectPermission { return &p }

func TestStaticCredentialStore_NilPermissionsDefaultsToRW(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret"}})
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if !credential.CanWrite() {
		t.Fatal("expected CanWrite() to be true for default rw permissions")
	}
}

func TestCredentialStore_BucketMatchExact(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret", Buckets: []string{"exact-bucket"}}})
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if !credential.AllowsBucket("exact-bucket") {
		t.Fatal("expected exact bucket to match")
	}
	if credential.AllowsBucket("other-bucket") {
		t.Fatal("expected non-matching bucket to be denied")
	}
}

func TestCredentialStore_BucketMatchTrailingWildcardPrefix(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "key", SecretKey: "secret", Buckets: []string{"tenant-*"}}})
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if !credential.AllowsBucket("tenant-a") {
		t.Fatal("expected tenant-a to match prefix")
	}
	if !credential.AllowsBucket("tenant-prod") {
		t.Fatal("expected tenant-prod to match prefix")
	}
	if credential.AllowsBucket("tenant") {
		t.Fatal("expected tenant (no trailing content) to be denied")
	}
	if credential.AllowsBucket("other-tenant") {
		t.Fatal("expected other-tenant to be denied")
	}
}

// TestCredentialStore_MutatingConstructorInputDoesNotAffectStore proves the
// store deep-copies constructor input: mutating the caller's slice after
// publication must not change stored policy data.
func TestCredentialStore_MutatingConstructorInputDoesNotAffectStore(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "key", SecretKey: "secret", Label: "original", Buckets: []string{"tenant-a"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the caller-owned slice and struct fields after publication.
	creds[0].AccessKey = "evil"
	creds[0].SecretKey = "evil-secret"
	creds[0].Label = "evil"
	creds[0].Buckets[0] = "evil-bucket"
	creds[0].BucketPermissions[0] = config.BucketPermissionDelete

	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatal(err)
	}
	if credential.AccessKey != "key" || credential.SecretKey != "secret" || credential.Label != "original" {
		t.Fatalf("store mutated by constructor input: %+v", credential)
	}
	if !credential.AllowsBucket("tenant-a") || credential.AllowsBucket("evil-bucket") {
		t.Fatalf("bucket scope mutated by constructor input: %+v", credential.Policy.Buckets)
	}
	if !credential.HasBucketPermission(config.BucketPermissionCreate) || credential.HasBucketPermission(config.BucketPermissionDelete) {
		t.Fatalf("bucket permissions mutated by constructor input: %+v", credential.Policy.BucketPermissions)
	}
}

// TestCredentialStore_MutatingReplaceInputDoesNotAffectStore proves Replace
// deep-copies its input before publishing the snapshot.
func TestCredentialStore_MutatingReplaceInputDoesNotAffectStore(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "seed", SecretKey: "seed"}})
	if err != nil {
		t.Fatal(err)
	}
	replacement := []config.GatewayCredential{
		{AccessKey: "key", SecretKey: "secret", Buckets: []string{"tenant-a"}},
	}
	if err := store.Replace(replacement); err != nil {
		t.Fatal(err)
	}
	replacement[0].AccessKey = "evil"
	replacement[0].Buckets[0] = "evil-bucket"

	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatal(err)
	}
	if credential.AccessKey != "key" {
		t.Fatalf("access key mutated by Replace input: %q", credential.AccessKey)
	}
	if credential.AllowsBucket("evil-bucket") || !credential.AllowsBucket("tenant-a") {
		t.Fatalf("bucket scope mutated by Replace input: %+v", credential.Policy.Buckets)
	}
}

// TestCredentialStore_MutatingLookupResultDoesNotAffectStore proves Lookup
// returns an independent copy: mutating the result must not leak into later
// lookups or the stored snapshot.
func TestCredentialStore_MutatingLookupResultDoesNotAffectStore(t *testing.T) {
	store, err := NewStaticCredentialStore([]config.GatewayCredential{
		{AccessKey: "key", SecretKey: "secret", Buckets: []string{"tenant-a"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Lookup("key")
	if err != nil {
		t.Fatal(err)
	}
	credential.Policy.Buckets[0] = "evil-bucket"
	credential.Policy.BucketPermissions[0] = config.BucketPermissionDelete
	credential.AccessKey = "evil"
	credential.SecretKey = "evil-secret"

	again, err := store.Lookup("key")
	if err != nil {
		t.Fatal(err)
	}
	if again.AccessKey != "key" || again.SecretKey != "secret" {
		t.Fatalf("lookup result mutation leaked: %+v", again)
	}
	if again.AllowsBucket("evil-bucket") || !again.AllowsBucket("tenant-a") {
		t.Fatalf("lookup result bucket mutation leaked: %+v", again.Policy.Buckets)
	}
	if again.HasBucketPermission(config.BucketPermissionDelete) || !again.HasBucketPermission(config.BucketPermissionCreate) {
		t.Fatalf("lookup result permission mutation leaked: %+v", again.Policy.BucketPermissions)
	}
}

// TestCredentialStore_ConcurrentReplacementIsCoherent alternates two complete
// distinguishable snapshots while readers look up both keys, and asserts every
// individual lookup is coherent: all of its fields match exactly one complete
// snapshot (old OR new), never a mix. Field-level mixing would prove the store
// published partial state instead of one atomic snapshot swap.
func TestCredentialStore_ConcurrentReplacementIsCoherent(t *testing.T) {
	snapshotA := []config.GatewayCredential{
		{AccessKey: "alpha", SecretKey: "alpha-secret", Label: "alpha-A", Buckets: []string{"a-*"}},
		{AccessKey: "beta", SecretKey: "beta-secret", Label: "beta-A", Buckets: []string{"b-*"}},
	}
	snapshotB := []config.GatewayCredential{
		{AccessKey: "alpha", SecretKey: "alpha-secret", Label: "alpha-B", Buckets: []string{"b-*"}},
		{AccessKey: "beta", SecretKey: "beta-secret", Label: "beta-B", Buckets: []string{"a-*"}},
	}
	store, err := NewStaticCredentialStore(snapshotA)
	if err != nil {
		t.Fatal(err)
	}

	// coherent reports whether (label, scope) matches exactly one snapshot.
	coherent := func(label string, allowsA, allowsB bool) bool {
		switch label {
		case "alpha-A", "beta-A":
			return (label == "alpha-A" && allowsA && !allowsB) || (label == "beta-A" && allowsB && !allowsA)
		case "alpha-B", "beta-B":
			return (label == "alpha-B" && allowsB && !allowsA) || (label == "beta-B" && allowsA && !allowsB)
		default:
			return false
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				if err := store.Replace(snapshotA); err != nil {
					t.Error(err)
					return
				}
			} else {
				if err := store.Replace(snapshotB); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				for _, key := range []string{"alpha", "beta"} {
					credential, err := store.Lookup(key)
					if err != nil {
						t.Error(err)
						return
					}
					allowsA := credential.AllowsBucket("a-bucket")
					allowsB := credential.AllowsBucket("b-bucket")
					if !coherent(credential.Label, allowsA, allowsB) {
						t.Errorf("mixed snapshot observed for %s: label=%q buckets=%v", key, credential.Label, credential.Policy.Buckets)
						return
					}
				}
			}
		}()
	}
	close(stop)
	wg.Wait()
}
