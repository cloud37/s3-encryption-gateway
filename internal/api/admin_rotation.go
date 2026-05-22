package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/admin"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/sirupsen/logrus"
)

// AdminRotationHandler manages the /admin/kms/rotate/* endpoints.
type AdminRotationHandler struct {
	engine       crypto.EncryptionEngine
	logger       *logrus.Logger
	metrics      *metrics.Metrics
	auditLogger  audit.Logger
}

// NewAdminRotationHandler creates new rotation admin handlers.
func NewAdminRotationHandler(
	engine crypto.EncryptionEngine,
	logger *logrus.Logger,
	m *metrics.Metrics,
	auditLogger audit.Logger,
) *AdminRotationHandler {
	return &AdminRotationHandler{
		engine:      engine,
		logger:      logger,
		metrics:     m,
		auditLogger: auditLogger,
	}
}

// RegisterRoutes mounts the rotation endpoints on the admin mux.
func (h *AdminRotationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/kms/rotate/start", h.handleRotateStart)
	mux.HandleFunc("GET /admin/kms/rotate/status", h.handleRotateStatus)
	mux.HandleFunc("POST /admin/kms/rotate/commit", h.handleRotateCommit)
	mux.HandleFunc("POST /admin/kms/rotate/abort", h.handleRotateAbort)
}

// --- Request/Response types ---

type rotateStartRequest struct {
	TargetVersion *int   `json:"target_version,omitempty"`
	GracePeriod   string `json:"grace_period,omitempty"` // Go duration string, e.g. "30s"
}

type rotateStartResponse struct {
	RotationID     string `json:"rotation_id"`
	Phase          string `json:"phase"`
	CurrentVersion int    `json:"current_version"`
	TargetVersion  int    `json:"target_version"`
	GraceDeadline  string `json:"grace_deadline,omitempty"`
	Provider       string `json:"provider"`
}

type rotateCommitRequest struct {
	Force bool `json:"force,omitempty"`
}

// --- Handlers ---

func (h *AdminRotationHandler) handleRotateStart(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	km := crypto.GetKeyManager(h.engine)
	if km == nil {
		admin.WriteAdminErrorWithRotation(w, http.StatusNotImplemented, "NotImplemented", "no key manager configured", "")
		h.recordMetric("start", "error", start)
		return
	}

	rkm, ok := km.(crypto.RotatableKeyManager)
	if !ok {
		admin.WriteAdminErrorWithRotation(w, http.StatusNotImplemented, "NotImplemented",
			fmt.Sprintf("key manager %q does not support rotation", km.Provider()), "")
		h.recordMetric("start", "unsupported", start)
		return
	}

	// Parse request body
	var req rotateStartRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			admin.WriteAdminErrorWithRotation(w, http.StatusBadRequest, "BadRequest", "invalid request body: "+err.Error(), "")
			return
		}
	}

	// Parse grace period
	gracePeriod := 30 * time.Second // default
	if req.GracePeriod != "" {
		d, err := time.ParseDuration(req.GracePeriod)
		if err != nil {
			admin.WriteAdminErrorWithRotation(w, http.StatusBadRequest, "BadRequest", "invalid grace_period: "+err.Error(), "")
			return
		}
		gracePeriod = d
	}

	// Prepare rotation
	plan, err := rkm.PrepareRotation(r.Context(), req.TargetVersion)
	if err != nil {
		status := http.StatusInternalServerError
		code := "InternalError"
		if errors.Is(err, crypto.ErrRotationAmbiguous) {
			status = http.StatusBadRequest
			code = "AmbiguousTarget"
		} else if errors.Is(err, crypto.ErrKeyNotFound) {
			status = http.StatusNotFound
			code = "KeyNotFound"
		}
		admin.WriteAdminErrorWithRotation(w, status, code, err.Error(), "")
		h.recordMetric("start", "error", start)
		return
	}

	// Generate rotation ID
	rotationID := fmt.Sprintf("rot-%d-%d-to-%d", time.Now().UnixMilli(), plan.CurrentVersion, plan.TargetVersion)

	// Start drain
	rs := crypto.GetRotationState(h.engine)
	if err := rs.StartDrain(rotationID, plan.CurrentVersion, plan.TargetVersion, km.Provider(), &plan, gracePeriod); err != nil {
		if errors.Is(err, crypto.ErrRotationConflict) {
			snap := rs.Snapshot()
			admin.WriteAdminErrorWithRotation(w, http.StatusConflict, "RotationConflict", err.Error(), snap.RotationID)
		} else {
			admin.WriteAdminErrorWithRotation(w, http.StatusInternalServerError, "InternalError", err.Error(), "")
		}
		h.recordMetric("start", "conflict", start)
		return
	}

	// Audit
	h.auditRotation("key_rotation.start", rotationID, plan.CurrentVersion, plan.TargetVersion, km.Provider(), "")

	// Update active version metric
	if h.metrics != nil {
		h.metrics.SetActiveKeyVersion(km.Provider(), plan.CurrentVersion)
	}

	h.recordMetric("start", "ok", start)

	resp := rotateStartResponse{
		RotationID:     rotationID,
		Phase:          "draining",
		CurrentVersion: plan.CurrentVersion,
		TargetVersion:  plan.TargetVersion,
		Provider:       km.Provider(),
	}
	if gracePeriod > 0 {
		resp.GraceDeadline = time.Now().Add(gracePeriod).Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(resp)
}

func (h *AdminRotationHandler) handleRotateStatus(w http.ResponseWriter, r *http.Request) {
	rs := crypto.GetRotationState(h.engine)
	snap := rs.Snapshot()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

func (h *AdminRotationHandler) handleRotateCommit(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	km := crypto.GetKeyManager(h.engine)
	if km == nil {
		admin.WriteAdminErrorWithRotation(w, http.StatusNotImplemented, "NotImplemented", "no key manager configured", "")
		h.recordMetric("commit", "error", start)
		return
	}

	rkm, ok := km.(crypto.RotatableKeyManager)
	if !ok {
		admin.WriteAdminErrorWithRotation(w, http.StatusNotImplemented, "NotImplemented", "key manager does not support rotation", "")
		h.recordMetric("commit", "unsupported", start)
		return
	}

	var req rotateCommitRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			admin.WriteAdminErrorWithRotation(w, http.StatusBadRequest, "BadRequest", err.Error(), "")
			return
		}
	}

	rs := crypto.GetRotationState(h.engine)
	snap := rs.Snapshot()

	// Transition to Committing
	if err := rs.Commit(req.Force); err != nil {
		status := http.StatusConflict
		if errors.Is(err, crypto.ErrRotationConflict) {
			status = http.StatusConflict
		}
		admin.WriteAdminErrorWithRotation(w, status, "RotationConflict", err.Error(), snap.RotationID)
		h.recordMetric("commit", "conflict", start)
		return
	}

	// Promote the active version
	plan := crypto.RotationPlan{
		CurrentVersion: snap.CurrentVersion,
		TargetVersion:  snap.TargetVersion,
	}
	if snap.Plan != nil {
		plan.ProviderData = snap.Plan.ProviderData
	}

	if err := rkm.PromoteActiveVersion(r.Context(), plan); err != nil {
		rs.MarkFailed(err)
		h.auditRotation("key_rotation.commit_failed", snap.RotationID, snap.CurrentVersion, snap.TargetVersion, km.Provider(), err.Error())
		admin.WriteAdminErrorWithRotation(w, http.StatusInternalServerError, "PromoteFailed", err.Error(), snap.RotationID)
		h.recordMetric("commit", "error", start)
		return
	}

	rs.MarkCommitted()
	h.auditRotation("key_rotation.committed", snap.RotationID, snap.CurrentVersion, snap.TargetVersion, km.Provider(), "")

	// Update metric
	if h.metrics != nil {
		h.metrics.SetActiveKeyVersion(km.Provider(), snap.TargetVersion)
	}

	h.recordMetric("commit", "ok", start)

	// Return updated snapshot
	finalSnap := rs.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalSnap)
}

func (h *AdminRotationHandler) handleRotateAbort(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	km := crypto.GetKeyManager(h.engine)
	rs := crypto.GetRotationState(h.engine)
	snap := rs.Snapshot()

	if err := rs.Abort(); err != nil {
		admin.WriteAdminErrorWithRotation(w, http.StatusConflict, "RotationConflict", err.Error(), snap.RotationID)
		h.recordMetric("abort", "conflict", start)
		return
	}

	provider := ""
	if km != nil {
		provider = km.Provider()
	}
	h.auditRotation("key_rotation.aborted", snap.RotationID, snap.CurrentVersion, snap.TargetVersion, provider, "")
	h.recordMetric("abort", "ok", start)

	finalSnap := rs.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalSnap)
}

// --- Helpers ---

func (h *AdminRotationHandler) recordMetric(step, result string, start time.Time) {
	if h.metrics != nil {
		h.metrics.RecordRotationOperation(step, result, time.Since(start))
	}
}

func (h *AdminRotationHandler) auditRotation(eventType, rotationID string, currentVersion, targetVersion int, provider, errMsg string) {
	if h.auditLogger == nil {
		return
	}
	fields := map[string]interface{}{
		"event_type":      eventType,
		"rotation_id":     rotationID,
		"current_version": currentVersion,
		"target_version":  targetVersion,
		"provider":        provider,
	}
	if errMsg != "" {
		fields["error"] = errMsg
	}

	success := errMsg == ""
	var auditErr error
	if !success {
		auditErr = fmt.Errorf("%s", errMsg)
	}

	h.auditLogger.LogAccessWithMetadata(
		eventType,          // eventType
		"",                 // bucket
		"kms/rotation",     // key
		"admin",            // clientIP
		"admin-api",        // userAgent
		rotationID,         // requestID
		success,            // success
		auditErr,           // err
		0,                  // duration
		fields,             // metadata
	)

	h.logger.WithFields(logrus.Fields(fields)).Info("key rotation event")
}
