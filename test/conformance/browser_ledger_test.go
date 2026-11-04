package conformance

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
)

type browserLedgerEntry struct {
	Stage      string
	Request    harness.RequestObservation
	Checkpoint bool
}

type expectedBrowserStage struct {
	name, origin, requestedMethod, requestedHeaders string
	status                                          int
	allowOrigin                                     string
	wantPost                                        bool
}

type browserLedgerFailer interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
}

func assertBrowserLedger(t browserLedgerFailer, entries []browserLedgerEntry, session bool, bucketPath, allowedOrigin, deniedOrigin string) {
	t.Helper()
	expectedStages := expectedBrowserStages(session, allowedOrigin, deniedOrigin)
	if err := validateBrowserLedger(entries, expectedStages, bucketPath); err != nil {
		t.Fatalf("browser request ledger invalid: %v", err)
	}
}

func expectedBrowserStages(session bool, allowedOrigin, deniedOrigin string) []expectedBrowserStage {
	expectedStages := []expectedBrowserStage{
		{"default", allowedOrigin, "", "", http.StatusNoContent, allowedOrigin, true},
		{"default-read", allowedOrigin, "", "", 0, "", false},
		{"policy-denial", allowedOrigin, "", "", http.StatusForbidden, allowedOrigin, true},
		{"created", allowedOrigin, "", "", http.StatusCreated, allowedOrigin, true},
		{"created-read", allowedOrigin, "", "", 0, "", false},
		{"custom-allowed", allowedOrigin, "POST", "x-gh353-allowed", http.StatusNoContent, allowedOrigin, true},
		{"custom-read", allowedOrigin, "", "", 0, "", false},
		{"custom-denied", allowedOrigin, "POST", "x-gh353-denied", http.StatusForbidden, "", false},
		{"denied-origin", deniedOrigin, "", "", http.StatusNoContent, "", true},
		{"denied-origin-read", deniedOrigin, "", "", 0, "", false},
	}
	if session {
		expectedStages = append(expectedStages,
			expectedBrowserStage{"session-upload", allowedOrigin, "", "", http.StatusNoContent, allowedOrigin, true},
			expectedBrowserStage{"session-read", allowedOrigin, "", "", 0, "", false},
			expectedBrowserStage{"session-wrong-token", allowedOrigin, "", "", http.StatusForbidden, allowedOrigin, true},
			expectedBrowserStage{"session-missing-token", allowedOrigin, "", "", http.StatusForbidden, allowedOrigin, true})
	}
	return expectedStages
}

func validateBrowserLedger(entries []browserLedgerEntry, expectedStages []expectedBrowserStage, bucketPath string) error {
	if len(entries) == 0 {
		return fmt.Errorf("browser ledger contained no checkpoints or bucket-level arrivals")
	}
	checkpointIndices := make(map[string]int, len(expectedStages))
	for i, entry := range entries {
		if !entry.Checkpoint {
			continue
		}
		if _, exists := checkpointIndices[entry.Stage]; exists {
			return fmt.Errorf("duplicate checkpoint for stage %q", entry.Stage)
		}
		checkpointIndices[entry.Stage] = i
	}
	lastCheckpoint := -1
	for _, expected := range expectedStages {
		index, ok := checkpointIndices[expected.name]
		if !ok {
			return fmt.Errorf("browser stage %q did not emit its checkpoint", expected.name)
		}
		if index <= lastCheckpoint {
			return fmt.Errorf("browser stage %q checkpoint is out of sequence", expected.name)
		}
		lastCheckpoint = index
	}
	if err := validateBrowserArrivalOrder(entries); err != nil {
		return err
	}
	knownStages := make(map[string]struct{}, len(expectedStages))
	for _, expected := range expectedStages {
		knownStages[expected.name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := knownStages[entry.Stage]; !ok {
			return fmt.Errorf("unknown browser ledger stage %q", entry.Stage)
		}
	}
	for _, expected := range expectedStages {
		var stageRequests []harness.RequestObservation
		var stageCount int
		checkpointIndex := checkpointIndices[expected.name]
		nextCheckpointIndex := len(entries)
		for _, later := range expectedStages {
			if laterIndex := checkpointIndices[later.name]; laterIndex > checkpointIndex && laterIndex < nextCheckpointIndex {
				nextCheckpointIndex = laterIndex
			}
		}
		for entryIndex, entry := range entries {
			if entry.Stage == expected.name {
				if entry.Checkpoint {
					continue
				}
				stageCount++
				if entryIndex <= checkpointIndex || entryIndex >= nextCheckpointIndex {
					return fmt.Errorf("stage %q arrival is outside its checkpoint window", expected.name)
				}
				if entry.Request.Path != bucketPath {
					return fmt.Errorf("stage %q included unexpected request path %q", expected.name, entry.Request.Path)
				}
				stageRequests = append(stageRequests, entry.Request)
			}
		}
		if expected.status == 0 {
			if stageCount != 0 {
				return fmt.Errorf("readback checkpoint %q unexpectedly observed bucket-level upload requests", expected.name)
			}
			continue
		}
		if stageCount == 0 {
			return fmt.Errorf("stage %q was not recorded", expected.name)
		}
		var preflight *harness.RequestObservation
		var post *harness.RequestObservation
		for i := range stageRequests {
			request := &stageRequests[i]
			if request.Method == http.MethodOptions {
				if preflight != nil {
					return fmt.Errorf("stage %q had duplicate OPTIONS arrivals", expected.name)
				}
				preflight = request
			}
			if request.Method == http.MethodPost {
				if post != nil {
					return fmt.Errorf("stage %q had duplicate POST arrivals", expected.name)
				}
				post = request
			}
		}
		if expected.requestedHeaders != "" {
			preflightStatus := expected.status
			if expected.wantPost {
				preflightStatus = http.StatusOK
			}
			if preflight == nil || !strings.EqualFold(preflight.AccessControlRequestMethod, expected.requestedMethod) || !equalHeaderTokenSet(preflight.AccessControlRequestHeaders, expected.requestedHeaders) || preflight.Status != preflightStatus || preflight.Origin != expected.origin || preflight.AuthorizationPresent || preflight.AllowOrigin != expected.allowOrigin {
				return fmt.Errorf("stage %q preflight ledger mismatch: %+v", expected.name, preflight)
			}
			if expected.wantPost {
				if post == nil || post.Status != http.StatusNoContent || post.Origin != expected.origin || post.AllowOrigin != expected.allowOrigin || post.AuthorizationPresent {
					return fmt.Errorf("stage %q POST ledger mismatch: %+v", expected.name, post)
				}
				if indexOfRequest(stageRequests, preflight) >= indexOfRequest(stageRequests, post) {
					return fmt.Errorf("stage %q POST arrival did not follow its OPTIONS", expected.name)
				}
			} else if post != nil {
				return fmt.Errorf("stage %q had an unexpected POST arrival: %+v", expected.name, post)
			}
			continue
		}
		if preflight != nil {
			return fmt.Errorf("stage %q had an unexpected OPTIONS arrival: %+v", expected.name, preflight)
		}
		if expected.wantPost {
			authorizationMatches := post != nil && !post.AuthorizationPresent
			if post == nil || post.Status != expected.status || post.Origin != expected.origin || post.AllowOrigin != expected.allowOrigin || !authorizationMatches {
				return fmt.Errorf("stage %q POST ledger mismatch: %+v", expected.name, post)
			}
		} else if post != nil {
			return fmt.Errorf("stage %q had unexpected POST arrival: %+v", expected.name, post)
		}
	}
	return nil
}

func validateBrowserArrivalOrder(entries []browserLedgerEntry) error {
	for i, entry := range entries {
		if entry.Checkpoint || entry.Request.Method != http.MethodOptions {
			continue
		}
		if entry.Stage == "custom-denied" && entry.Request.Status == http.StatusForbidden {
			if hasLaterStagePost(entries[i+1:], entry.Stage) {
				return fmt.Errorf("denied OPTIONS arrival at index %d was followed by an unexpected POST", i)
			}
			continue
		}
		if i+1 >= len(entries) || entries[i+1].Checkpoint || entries[i+1].Stage != entry.Stage || entries[i+1].Request.Method != http.MethodPost {
			return fmt.Errorf("OPTIONS arrival at index %d was not immediately followed by its associated POST", i)
		}
	}
	return nil
}

func hasLaterStagePost(entries []browserLedgerEntry, stage string) bool {
	for _, entry := range entries {
		if entry.Checkpoint {
			return false
		}
		if entry.Stage == stage && entry.Request.Method == http.MethodPost {
			return true
		}
	}
	return false
}

func assertBrowserLedgerWithFailer(t browserLedgerFailer, entries []browserLedgerEntry, session bool, bucketPath, allowedOrigin, deniedOrigin string) {
	if err := validateBrowserLedger(entries, expectedBrowserStages(session, allowedOrigin, deniedOrigin), bucketPath); err != nil {
		t.Fatalf("browser request ledger invalid: %v", err)
	}
}

func equalHeaderTokenSet(value, expected string) bool {
	if expected == "" {
		return strings.TrimSpace(value) == ""
	}
	set := make(map[string]struct{})
	for _, token := range strings.Split(value, ",") {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
			set[token] = struct{}{}
		}
	}
	want := make(map[string]struct{})
	for _, token := range strings.Split(expected, ",") {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
			want[token] = struct{}{}
		}
	}
	if len(set) != len(want) {
		return false
	}
	for token := range want {
		if _, ok := set[token]; !ok {
			return false
		}
	}
	return true
}

func indexOfRequest(requests []harness.RequestObservation, target *harness.RequestObservation) int {
	for index := range requests {
		if &requests[index] == target {
			return index
		}
	}
	return -1
}

func startBrowserOrigin(t *testing.T, label string, stageMu *sync.Mutex, currentStage *string, stageLedger *[]browserLedgerEntry) (string, func()) {
	return startBrowserOriginWithSettleTimeout(t, label, stageMu, currentStage, stageLedger, 10*time.Second)
}

func startBrowserOriginWithSettleTimeout(t *testing.T, label string, stageMu *sync.Mutex, currentStage *string, stageLedger *[]browserLedgerEntry, settleTimeout time.Duration) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start browser %s origin listener", label)
	}
	t.Cleanup(func() { _ = listener.Close() })
	mux := http.NewServeMux()
	if stageMu != nil {
		mux.HandleFunc("/stage/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Vary", "Origin")
			if r.Method != http.MethodPost || r.URL.RawQuery != "" || strings.TrimSuffix(r.URL.Path, "/") != "/stage/"+strings.TrimPrefix(r.URL.Path, "/stage/") {
				http.Error(w, "invalid stage", http.StatusBadRequest)
				return
			}
			name := strings.TrimPrefix(r.URL.Path, "/stage/")
			if !isKnownBrowserStage(name) {
				http.Error(w, "invalid stage", http.StatusBadRequest)
				return
			}
			stageMu.Lock()
			previous := *currentStage
			stageMu.Unlock()
			if previous != "" {
				deadline := time.Now().Add(settleTimeout)
				for {
					stageMu.Lock()
					arrivals := append([]browserLedgerEntry(nil), (*stageLedger)...)
					stageMu.Unlock()
					if browserStageSettled(arrivals, previous) {
						break
					}
					if time.Now().After(deadline) {
						http.Error(w, "previous stage did not settle", http.StatusGatewayTimeout)
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			stageMu.Lock()
			*currentStage = name
			*stageLedger = append(*stageLedger, browserLedgerEntry{Stage: name, Checkpoint: true})
			stageMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>GH-353 browser fixture</title>")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	go func() { _ = server.Serve(listener) }()
	origin := "http://" + listener.Addr().String()
	return origin, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
	}
}

func countBrowserStageArrivals(entries []browserLedgerEntry, stage string) int {
	count := 0
	for _, entry := range entries {
		if entry.Stage == stage && !entry.Checkpoint {
			count++
		}
	}
	return count
}

func expectedBrowserStageArrivals(stage string) int {
	switch stage {
	case "custom-allowed":
		return 2
	case "default", "policy-denial", "created", "custom-denied", "denied-origin", "session-upload", "session-wrong-token", "session-missing-token":
		return 1
	default:
		return 0
	}
}

func browserStageSettled(entries []browserLedgerEntry, stage string) bool {
	if !isKnownBrowserStage(stage) {
		return false
	}
	arrivals := countBrowserStageArrivals(entries, stage)
	if isBrowserReadStage(stage) {
		return arrivals == 0
	}
	if arrivals < expectedBrowserStageArrivals(stage) {
		return false
	}
	var requests []harness.RequestObservation
	for _, entry := range entries {
		if entry.Stage == stage && !entry.Checkpoint {
			requests = append(requests, entry.Request)
		}
	}
	switch stage {
	case "custom-allowed":
		return hasStageMethods(requests, http.MethodOptions, http.MethodPost)
	case "custom-denied":
		return hasStageMethods(requests, http.MethodOptions) && !hasStageMethods(requests, http.MethodPost)
	default:
		return hasStageMethods(requests, http.MethodPost)
	}
}

func isKnownBrowserStage(stage string) bool {
	switch stage {
	case "default", "default-read", "policy-denial", "created", "created-read", "custom-allowed", "custom-read", "custom-denied", "denied-origin", "denied-origin-read", "session-upload", "session-read", "session-wrong-token", "session-missing-token":
		return true
	default:
		return false
	}
}

func isBrowserReadStage(stage string) bool {
	switch stage {
	case "default-read", "created-read", "custom-read", "denied-origin-read", "session-read":
		return true
	default:
		return false
	}
}

func hasStageMethods(requests []harness.RequestObservation, methods ...string) bool {
	seen := make(map[string]bool, len(methods))
	for _, request := range requests {
		for _, method := range methods {
			if request.Method == method {
				seen[method] = true
			}
		}
	}
	for _, method := range methods {
		if !seen[method] {
			return false
		}
	}
	return true
}
