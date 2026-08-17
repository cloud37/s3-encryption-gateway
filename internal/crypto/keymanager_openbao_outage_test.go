package crypto

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestOpenBao_Renewal_RecoversAfterOutage reproduces the production incident:
// OpenBao becomes unreachable long enough that the token dies, then comes back.
// The adapter must re-login on its own and become healthy again.
func TestOpenBao_Renewal_RecoversAfterOutage(t *testing.T) {
	srv := newMockBaoServer(t)
	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	if err := km.HealthCheck(context.Background()); err != nil {
		t.Fatalf("healthy at start: %v", err)
	}
	loginsBefore := srv.getLoginCount()

	// --- outage: every endpoint 5xxs, including login ---
	srv.setDown(500)
	time.Sleep(4 * time.Second) // lease is 2s, so the watcher fails and DoneCh fires

	if err := km.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected unhealthy during outage")
	}

	// The lease could not be renewed across the outage, so the token is gone.
	srv.expireIssuedTokens()

	// --- recovery: server is back, but the old token is dead ---
	srv.setDown(0)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := km.HealthCheck(context.Background()); err == nil {
			t.Logf("recovered after %d re-logins", srv.getLoginCount()-loginsBefore)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("did NOT recover within 30s of OpenBao returning; logins since outage=%d, last health=%v",
		srv.getLoginCount()-loginsBefore, km.HealthCheck(context.Background()))
}

// TestOpenBao_RecoversFromRevokedTokenWhileServerHealthy isolates the defect
// behind the production incident.
//
// The token is revoked (max_ttl reached / revoked / lease lost across an outage)
// while OpenBao itself is perfectly reachable. A single re-login restores
// service, and the login endpoint is available the whole time, so the adapter
// must not sit on the dead token waiting for the lease clock.
//
// Without the reactive path this fails: the LifetimeWatcher only reports a
// renewal failure at its next scheduled renewal, and nothing on the data path
// triggers a re-login, so every request 403s for up to a full lease period (1h in
// production).
//
// Recovery is transparent to the caller — the rejected request re-authenticates
// and retries in place — so the assertion is that the call SUCCEEDS and that a
// fresh login is what made it succeed.
func TestOpenBao_RecoversFromRevokedTokenWhileServerHealthy(t *testing.T) {
	srv := newMockBaoServer(t)
	// A long lease: this is the window the adapter must NOT wait out. Production
	// issues 3600s.
	srv.setLease(3600)

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "kubernetes", Role: "s3-gateway", JWT: "jwt"},
		Timeout: 30 * time.Second, // room for the login floor without tripping the deadline
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	if err := km.HealthCheck(context.Background()); err != nil {
		t.Fatalf("healthy at start: %v", err)
	}

	// Kill the token. The server stays up and the login endpoint stays open.
	loginsBefore := srv.getLoginCount()
	srv.expireIssuedTokens()

	// One call is enough: it 403s internally, re-authenticates, and retries.
	// Bounded by minLoginInterval, so allow a little slack but not a lease.
	start := time.Now()
	if err := km.HealthCheck(context.Background()); err != nil {
		t.Fatalf("did not recover from a revoked token: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("recovery took %v; expected roughly the login floor, not a lease", elapsed)
	}
	if logins := srv.getLoginCount() - loginsBefore; logins < 1 {
		t.Errorf("recovered without logging in (%d logins) — the old token cannot have worked", logins)
	}

	// The data path must work too, not just the probe.
	if _, err := km.WrapKey(context.Background(), make([]byte, 32), nil); err != nil {
		t.Fatalf("WrapKey after recovery: %v", err)
	}
}

// TestOpenBao_ReauthIsCoalesced asserts that a burst of concurrent requests
// hitting a dead token produces exactly ONE re-login, not one per request.
// Without the auth-generation check, a busy gateway would answer a revoked
// token with a login storm against an already-struggling OpenBao.
func TestOpenBao_ReauthIsCoalesced(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setLease(3600)

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "kubernetes", Role: "s3-gateway", JWT: "jwt"},
		Timeout: 2 * time.Second,
		// Renewal off: the watcher issues its first renew-self immediately on
		// start, which would race the revocation below and contribute a second,
		// legitimate login. This test is about the DATA path coalescing, so the
		// background path is excluded to keep the count exact.
		DisableRenewal: true,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Back-date the startup login so the attempt floor is already satisfied:
	// this test is about coalescing, not throttling.
	m := km.(*openBaoTransitManager)
	m.authSem <- struct{}{}
	m.lastLoginAttempt = time.Now().Add(-time.Hour)
	<-m.authSem

	loginsBefore := srv.getLoginCount()
	srv.expireIssuedTokens()

	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = km.WrapKey(context.Background(), make([]byte, 32), nil)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("WrapKey[%d] failed after re-auth: %v", i, e)
		}
	}
	if logins := srv.getLoginCount() - loginsBefore; logins != 1 {
		t.Errorf("expected exactly 1 coalesced re-login for %d concurrent 403s, got %d", n, logins)
	}
}

// TestOpenBao_BackgroundRenewalRecoversRevokedToken covers the PROACTIVE path in
// isolation: the renewal goroutine must notice a dead token and re-login with no
// help from the data path.
//
// The test deliberately makes no WrapKey/HealthCheck calls while waiting, so
// withAuthRetry cannot be what recovers it — only the LifetimeWatcher firing
// DoneCh and the loop re-logging-in can move loginCount.
func TestOpenBao_BackgroundRenewalRecoversRevokedToken(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setLease(4)

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	loginsBefore := srv.getLoginCount()
	srv.expireIssuedTokens()

	// Poll ONLY the server's login counter — no calls into km.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if srv.getLoginCount() > loginsBefore {
			// And the new token must actually work.
			if err := km.HealthCheck(context.Background()); err != nil {
				t.Fatalf("token from background re-login is not usable: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("renewal goroutine never re-logged-in after the token was revoked")
}

// TestOpenBao_DeadTokenDoesNotStormRenewals pins the RenewBehavior fix.
//
// Under the default RenewBehaviorIgnoreErrors, a failing renew-self does not end
// the watch AND the library leaves sleepDuration at zero on the error path, so
// the watcher busy-loops on renew-self until the grace window near the end of
// the original lease. With a production token_ttl of 1h that is minutes of
// unthrottled requests aimed at an OpenBao that is, by construction, already
// having a bad day — and every gateway replica does it at once.
//
// RenewBehaviorErrorOnErrors ends the watch on the first failure so the loop
// re-logs-in instead of spinning.
//
// Note the watcher issues its first renew-self IMMEDIATELY on Start, with no
// initial sleep, so the rejected renewal here happens at t~=0 rather than
// part-way through the lease.
func TestOpenBao_DeadTokenDoesNotStormRenewals(t *testing.T) {
	srv := newMockBaoServer(t)
	const leaseSec = 6
	srv.setLease(leaseSec)

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Kill the token immediately; the watcher's first renew-self (issued on
	// Start, without waiting) is therefore rejected. Make no data-path calls, so
	// only the watcher generates load.
	srv.expireIssuedTokens()
	before := srv.getRequestCount()

	time.Sleep((leaseSec + 1) * time.Second)

	// A sane implementation spends a handful of requests here: one rejected
	// renewal, one login, and the renewals of the fresh lease. A spinning
	// watcher spends thousands.
	const budget = 25
	if got := srv.getRequestCount() - before; got > budget {
		t.Errorf("watcher stormed OpenBao after the token died: %d requests in %ds (budget %d)",
			got, leaseSec+1, budget)
	}
}

// TestOpenBao_RenewIncapableRoleDoesNotStormLogins is the regression test for the
// storm that RenewBehaviorErrorOnErrors introduces if the loop re-logs-in
// unconditionally.
//
// The role can log in but cannot renew-self — the shape produced by
// token_no_default_policy with only auth/token/lookup-self granted, which is what
// docs/KMS_COMPATIBILITY.md tells operators to configure. Every watcher therefore
// dies on its first renewal, and an unguarded loop answers each death with a
// fresh login: measured at 21,741 logins in 3s before the fix. Each of those is
// real server state, so the KMS lease table grows until storage does — strictly
// worse than the renew-self spin ErrorOnErrors exists to prevent.
func TestOpenBao_RenewIncapableRoleDoesNotStormLogins(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setLease(3600)
	srv.setRenewStatus(403) // login works; renew-self never will

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	loginsBefore := srv.getLoginCount()

	// The window is long enough to discriminate the two guards, not just the
	// cheaper one. The per-attempt floor alone would allow ~1 login/second — over
	// a day that is still ~86k tokens in the KMS lease table. The renewal loop's
	// exponential backoff (1s, 2s, 4s, 8s...) is what turns that into a handful,
	// so the budget below is set under what the floor alone would produce.
	const window = 12 * time.Second
	time.Sleep(window)

	const budget = 6 // floor-only would be ~12; escalating backoff gives ~4
	if logins := srv.getLoginCount() - loginsBefore; logins > budget {
		t.Errorf("login storm: %d logins in %v for a renew-incapable role (budget %d)",
			logins, window, budget)
	}
	if err := km.HealthCheck(context.Background()); err != nil {
		t.Errorf("token should still be usable despite being unrenewable: %v", err)
	}
}

// TestOpenBao_TokenDyingMidLeaseIsRecovered covers the SCHEDULED renewal path,
// which the other tests miss: the LifetimeWatcher issues its first renew-self
// immediately on Start, so a token killed before construction is always caught by
// that t=0 renewal rather than by a scheduled one.
//
// Here the t=0 renewal succeeds and the token is killed afterwards, so the
// failure is discovered by the next scheduled renewal (~2/3 of the lease in).
// That is the "renewals worked, then stopped" case, which must be answered with a
// prompt re-login rather than the backoff reserved for a lease that was never
// renewable at all.
func TestOpenBao_TokenDyingMidLeaseIsRecovered(t *testing.T) {
	srv := newMockBaoServer(t)
	srv.setLease(4)

	km, err := NewOpenBaoTransitManager(OpenBaoTransitOptions{
		Address: srv.URL,
		KeyName: "test-key",
		Auth:    OpenBaoAuthConfig{Method: "approle", RoleID: "rid", SecretID: "sid"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Let the immediate t=0 renewal land first, so `renewed` is set.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := srv.renewCount
		srv.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	srv.mu.Lock()
	renewsBefore := srv.renewCount
	srv.mu.Unlock()
	if renewsBefore == 0 {
		t.Fatal("expected the watcher's initial renewal to succeed before the token is killed")
	}

	loginsBefore := srv.getLoginCount()
	srv.expireIssuedTokens() // dies mid-lease, after having renewed fine

	// The next scheduled renewal must notice and re-login. Generous budget: the
	// point is that it does not wait out the lease, not the exact instant.
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if srv.getLoginCount() > loginsBefore {
			if err := km.HealthCheck(context.Background()); err != nil {
				t.Fatalf("unhealthy after mid-lease recovery: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("a token that died mid-lease was never recovered by the scheduled renewal")
}
