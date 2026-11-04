package provider

import (
	"context"
	"testing"
)

func TestGH353ExternalCleanupPolicies(t *testing.T) {
	deleteProvider := &externalProvider{cleanup: CleanupPolicyDelete}
	retainProvider := &externalProvider{cleanup: CleanupPolicySkipDelete}
	if !deleteProvider.prefixCleanupEnabled(context.Background()) {
		t.Fatal("general delete-provider cleanup changed")
	}
	if deleteProvider.prefixCleanupEnabled(WithOwnedKeyCleanup(context.Background())) {
		t.Fatal("focused owned-key mode enabled prefix cleanup")
	}
	if retainProvider.prefixCleanupEnabled(context.Background()) || retainProvider.prefixCleanupEnabled(WithOwnedKeyCleanup(context.Background())) {
		t.Fatal("skip-delete provider enabled prefix cleanup")
	}
}
