package conformance

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
)

func TestGH353BrowserArrivalLedgerUsesBucketPathAndStageBoundaries(t *testing.T) {
	allowed := "http://allowed.example"
	denied := "http://denied.example"
	path := "/test-bucket"
	entries := runBrowserCheckpointSequence(t, path, allowed, denied, false)
	if err := browserLedgerError(entries, false, path, allowed, denied); err != nil {
		t.Fatalf("checkpoint-server static ledger rejected wire evidence: %v", err)
	}

	wrongPath := append([]browserLedgerEntry(nil), entries...)
	for i := range wrongPath {
		if wrongPath[i].Stage == "default" && !wrongPath[i].Checkpoint {
			wrongPath[i].Request.Path = "/test-bucket/object%2Fwith%2Fslash"
			break
		}
	}
	if err := browserLedgerError(wrongPath, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted an object-path POST filter instead of actual bucket-level arrival")
	}
	readbackPath := append([]browserLedgerEntry(nil), entries...)
	for i := range readbackPath {
		if readbackPath[i].Stage == "default" && !readbackPath[i].Checkpoint {
			readbackPath[i].Request.Path = "/test-bucket/object/with/slash"
			break
		}
	}
	if err := browserLedgerError(readbackPath, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted an object GET/HEAD/range path as bucket-level POST evidence")
	}
	misplacedArrival := append([]browserLedgerEntry(nil), entries...)
	var firstCheckpoint, firstArrival int
	for i, entry := range misplacedArrival {
		if entry.Stage == "default" {
			if entry.Checkpoint {
				firstCheckpoint = i
			} else {
				firstArrival = i
			}
		}
	}
	misplacedArrival[firstCheckpoint], misplacedArrival[firstArrival] = misplacedArrival[firstArrival], misplacedArrival[firstCheckpoint]
	if err := browserLedgerError(misplacedArrival, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted an arrival preceding its stage checkpoint")
	}

	missingPreflight := append([]browserLedgerEntry(nil), entries...)
	for i, entry := range missingPreflight {
		if entry.Stage == "custom-allowed" && entry.Request.Method == "OPTIONS" {
			missingPreflight = append(missingPreflight[:i], missingPreflight[i+1:]...)
			break
		}
	}
	if err := browserLedgerError(missingPreflight, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted a POST with no allowed OPTIONS in its own stage")
	}
	deniedWithUnexpectedPost := append([]browserLedgerEntry(nil), entries...)
	deniedWithUnexpectedPost = append(deniedWithUnexpectedPost, browserLedgerEntry{Stage: "custom-denied", Request: harness.RequestObservation{Method: "POST", Path: path, Status: 204, Origin: allowed}})
	if err := browserLedgerError(deniedWithUnexpectedPost, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted a POST after a denied preflight")
	}
	wrongDeniedStatus := append([]browserLedgerEntry(nil), entries...)
	for i := range wrongDeniedStatus {
		if wrongDeniedStatus[i].Stage == "custom-denied" && !wrongDeniedStatus[i].Checkpoint {
			wrongDeniedStatus[i].Request.Status = 204
			break
		}
	}
	if err := browserLedgerError(wrongDeniedStatus, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted a non-403 denied preflight")
	}
	unknownStage := append([]browserLedgerEntry(nil), entries...)
	unknownStage = append(unknownStage, browserLedgerEntry{Stage: "invented-stage", Checkpoint: true})
	if err := browserLedgerError(unknownStage, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted an unknown checkpoint stage")
	}
	postBeforeOptions := append([]browserLedgerEntry(nil), entries...)
	postIndex, optionsIndex := -1, -1
	for i, entry := range postBeforeOptions {
		if entry.Stage == "custom-allowed" && !entry.Checkpoint {
			if entry.Request.Method == http.MethodOptions {
				optionsIndex = i
			} else if entry.Request.Method == http.MethodPost {
				postIndex = i
			}
		}
	}
	postBeforeOptions[postIndex], postBeforeOptions[optionsIndex] = postBeforeOptions[optionsIndex], postBeforeOptions[postIndex]
	if err := browserLedgerError(postBeforeOptions, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted POST-before-OPTIONS ordering")
	}
	extraHeaderToken := append([]browserLedgerEntry(nil), entries...)
	for i := range extraHeaderToken {
		if extraHeaderToken[i].Stage == "custom-allowed" && extraHeaderToken[i].Request.Method == http.MethodOptions {
			extraHeaderToken[i].Request.AccessControlRequestHeaders = "x-gh353-allowed,x-gh353-allowed-evil"
			break
		}
	}
	if err := browserLedgerError(extraHeaderToken, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted an unexpected extra requested-header token")
	}
	credentialedOptions := append([]browserLedgerEntry(nil), entries...)
	for i := range credentialedOptions {
		if credentialedOptions[i].Stage == "custom-allowed" && credentialedOptions[i].Request.Method == http.MethodOptions {
			credentialedOptions[i].Request.AuthorizationPresent = true
			break
		}
	}
	if err := browserLedgerError(credentialedOptions, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted Authorization on an OPTIONS preflight")
	}
	deniedOriginMissingPost := append([]browserLedgerEntry(nil), entries...)
	for i, entry := range deniedOriginMissingPost {
		if entry.Stage == "denied-origin" && !entry.Checkpoint {
			deniedOriginMissingPost = append(deniedOriginMissingPost[:i], deniedOriginMissingPost[i+1:]...)
			break
		}
	}
	if err := browserLedgerError(deniedOriginMissingPost, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted denied-origin TypeError without an arriving POST")
	}
	deniedOriginReadable := append([]browserLedgerEntry(nil), entries...)
	for i, entry := range deniedOriginReadable {
		if entry.Stage == "denied-origin" && !entry.Checkpoint {
			deniedOriginReadable[i].Request.AllowOrigin = denied
			break
		}
	}
	if err := browserLedgerError(deniedOriginReadable, false, path, allowed, denied); err == nil {
		t.Fatal("ledger accepted a denied-origin POST with ACAO")
	}

	wrongToken := runBrowserCheckpointSequence(t, path, allowed, denied, true)
	if err := browserLedgerError(wrongToken, true, path, allowed, denied); err != nil {
		t.Fatalf("session ledger rejected form-policy signed session arrivals: %v", err)
	}
	missingTokenDenial := append([]browserLedgerEntry(nil), wrongToken...)
	for i, entry := range missingTokenDenial {
		if entry.Stage == "session-missing-token" && !entry.Checkpoint {
			missingTokenDenial = append(missingTokenDenial[:i], missingTokenDenial[i+1:]...)
			break
		}
	}
	if err := browserLedgerError(missingTokenDenial, true, path, allowed, denied); err == nil {
		t.Fatal("session ledger accepted a missing-token TypeError without a denied POST arrival")
	}
	wrongTokenDenial := append([]browserLedgerEntry(nil), wrongToken...)
	for i, entry := range wrongTokenDenial {
		if entry.Stage == "session-wrong-token" && !entry.Checkpoint {
			wrongTokenDenial = append(wrongTokenDenial[:i], wrongTokenDenial[i+1:]...)
			break
		}
	}
	if err := browserLedgerError(wrongTokenDenial, true, path, allowed, denied); err == nil {
		t.Fatal("session ledger accepted a wrong-token TypeError without a denied POST arrival")
	}
}

func TestGH353BrowserCheckpointServerSettlesStaticAndSessionStages(t *testing.T) {
	allowed, denied, bucketPath := "http://allowed.example", "http://denied.example", "/test-bucket"
	for _, session := range []bool{false, true} {
		entries := runBrowserCheckpointSequence(t, bucketPath, allowed, denied, session)
		if err := validateBrowserLedger(entries, expectedBrowserStages(session, allowed, denied), bucketPath); err != nil {
			t.Fatalf("session=%t checkpoint server ledger invalid: %v", session, err)
		}
	}
}

func TestGH353BrowserStageSettlingClassifiesEveryFixedStage(t *testing.T) {
	for _, stage := range []string{"default-read", "created-read", "custom-read", "denied-origin-read", "session-read"} {
		if !browserStageSettled(nil, stage) {
			t.Errorf("read checkpoint %q did not settle with zero bucket-level arrivals", stage)
		}
	}
	for _, stage := range []string{"default", "policy-denial", "created", "custom-allowed", "custom-denied", "denied-origin", "session-upload", "session-wrong-token", "session-missing-token"} {
		if browserStageSettled(nil, stage) {
			t.Errorf("upload checkpoint %q settled before required arrival evidence", stage)
		}
	}
	if browserStageSettled(nil, "unknown-stage") {
		t.Fatal("unknown checkpoint stage unexpectedly settled")
	}
	if browserStageSettled([]browserLedgerEntry{{Stage: "default-read", Request: harness.RequestObservation{Method: http.MethodPost}}}, "default-read") {
		t.Fatal("read checkpoint settled despite an unexpected bucket-level upload arrival")
	}
	if !browserStageSettled([]browserLedgerEntry{
		{Stage: "custom-allowed", Request: harness.RequestObservation{Method: http.MethodOptions}},
		{Stage: "custom-allowed", Request: harness.RequestObservation{Method: http.MethodPost}},
	}, "custom-allowed") {
		t.Fatal("custom-allowed checkpoint did not settle after OPTIONS and POST")
	}
	if !browserStageSettled([]browserLedgerEntry{{Stage: "custom-denied", Request: harness.RequestObservation{Method: http.MethodOptions}}}, "custom-denied") {
		t.Fatal("custom-denied checkpoint did not settle after OPTIONS without POST")
	}
}

func TestGH353BrowserCheckpointServerRejectsUnknownAndWaitsForArrival(t *testing.T) {
	var mu sync.Mutex
	currentStage := ""
	var ledger []browserLedgerEntry
	origin, closeServer := startBrowserOriginWithSettleTimeout(t, "checkpoint-wait", &mu, &currentStage, &ledger, 75*time.Millisecond)
	defer closeServer()
	client := &http.Client{Timeout: time.Second}
	post := func(stage string) int {
		request, err := http.NewRequest(http.MethodPost, origin+"/stage/"+stage, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if status := post("default"); status != http.StatusNoContent {
		t.Fatalf("initial checkpoint returned %d", status)
	}
	start := time.Now()
	if status := post("default-read"); status != http.StatusGatewayTimeout {
		t.Fatalf("checkpoint advanced without its required bucket POST: HTTP %d", status)
	}
	if time.Since(start) > time.Second {
		t.Fatal("missing-arrival checkpoint wait exceeded bound")
	}
	mu.Lock()
	stageAfterTimeout := currentStage
	mu.Unlock()
	if stageAfterTimeout != "default" {
		t.Fatalf("failed transition changed active stage to %q", stageAfterTimeout)
	}
	if status := post("not-a-stage"); status != http.StatusBadRequest {
		t.Fatalf("unknown stage returned HTTP %d", status)
	}
}

func runBrowserCheckpointSequence(t *testing.T, bucketPath, allowedOrigin, deniedOrigin string, session bool) []browserLedgerEntry {
	t.Helper()
	var mu sync.Mutex
	currentStage := ""
	var ledger []browserLedgerEntry
	stageOrigin, closeStage := startBrowserOriginWithSettleTimeout(t, "checkpoint-regression", &mu, &currentStage, &ledger, 250*time.Millisecond)
	client := &http.Client{Timeout: time.Second}
	postStage := func(stage string) int {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, stageOrigin+"/stage/"+stage, nil)
		if err != nil {
			t.Fatalf("construct checkpoint request: %v", err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("checkpoint %q request failed: %v", stage, err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	record := func(request harness.RequestObservation) {
		t.Helper()
		mu.Lock()
		ledger = append(ledger, browserLedgerEntry{Stage: currentStage, Request: request})
		mu.Unlock()
	}
	checkpoint := func(stage string) {
		t.Helper()
		if status := postStage(stage); status != http.StatusNoContent {
			t.Fatalf("checkpoint %q returned HTTP %d", stage, status)
		}
	}
	defer closeStage()

	for _, expected := range expectedBrowserStages(session, allowedOrigin, deniedOrigin) {
		checkpoint(expected.name)
		requests := regressionRequests(expected.name, bucketPath, allowedOrigin, deniedOrigin)
		if len(requests) == 0 {
			if !browserStageSettled(snapshotBrowserLedger(&mu, &ledger), expected.name) {
				t.Fatalf("read stage %q did not settle with zero bucket arrivals", expected.name)
			}
			continue
		}
		if expected.name == "custom-allowed" {
			record(requests[0])
			if status := postStage("custom-read"); status != http.StatusGatewayTimeout {
				t.Fatalf("custom-allowed advanced before its POST arrival: HTTP %d", status)
			}
			record(requests[1])
			continue
		}
		for _, request := range requests {
			record(request)
		}
	}
	return snapshotBrowserLedger(&mu, &ledger)
}

func regressionRequests(stage, bucketPath, allowedOrigin, deniedOrigin string) []harness.RequestObservation {
	post := func(status int, origin, allowOrigin string) harness.RequestObservation {
		return harness.RequestObservation{Method: http.MethodPost, Path: bucketPath, Status: status, Origin: origin, AllowOrigin: allowOrigin}
	}
	switch stage {
	case "default", "session-upload":
		return []harness.RequestObservation{post(http.StatusNoContent, allowedOrigin, allowedOrigin)}
	case "policy-denial", "session-wrong-token", "session-missing-token":
		return []harness.RequestObservation{post(http.StatusForbidden, allowedOrigin, allowedOrigin)}
	case "created":
		return []harness.RequestObservation{post(http.StatusCreated, allowedOrigin, allowedOrigin)}
	case "custom-allowed":
		return []harness.RequestObservation{
			{Method: http.MethodOptions, Path: bucketPath, Status: http.StatusOK, Origin: allowedOrigin, AccessControlRequestMethod: "POST", AccessControlRequestHeaders: "X-GH353-Allowed", AllowOrigin: allowedOrigin},
			post(http.StatusNoContent, allowedOrigin, allowedOrigin),
		}
	case "custom-denied":
		return []harness.RequestObservation{{Method: http.MethodOptions, Path: bucketPath, Status: http.StatusForbidden, Origin: allowedOrigin, AccessControlRequestMethod: "POST", AccessControlRequestHeaders: "x-gh353-denied"}}
	case "denied-origin":
		return []harness.RequestObservation{post(http.StatusNoContent, deniedOrigin, "")}
	default:
		return nil
	}
}

func snapshotBrowserLedger(mu *sync.Mutex, ledger *[]browserLedgerEntry) []browserLedgerEntry {
	mu.Lock()
	defer mu.Unlock()
	return append([]browserLedgerEntry(nil), (*ledger)...)
}

func browserLedgerError(entries []browserLedgerEntry, session bool, path, allowed, denied string) (failure error) {
	tester := &recordingTester{}
	assertBrowserLedgerWithFailer(tester, entries, session, path, allowed, denied)
	return tester.failure
}

type recordingTester struct{ failure error }

func (r *recordingTester) Helper()                           {}
func (r *recordingTester) Fatal(args ...any)                 { r.failure = fmt.Errorf("%v", args) }
func (r *recordingTester) Fatalf(format string, args ...any) { r.failure = fmt.Errorf(format, args...) }
