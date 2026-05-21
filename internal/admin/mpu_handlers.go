package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/mpu"
	"github.com/sirupsen/logrus"
)

// MPUStateStore is the subset of mpu.StateStore used by the admin handlers.
// Separating the interface allows mocking in tests without the full store.
type MPUStateStore interface {
	Get(ctx context.Context, uploadID string) (*mpu.UploadState, error)
	Delete(ctx context.Context, uploadID string) error
	List(ctx context.Context) ([]mpu.UploadState, error)
}

// MPUAbortFunc is called by the admin abort endpoint to also abort the backend upload.
type MPUAbortFunc func(ctx context.Context, bucket, key, uploadID string) error

// RegisterMPUAdminRoutes mounts the MPU admin endpoints on the provided mux.
//
//	POST /admin/mpu/abort/{uploadId}  — force-abort an in-flight upload
//	GET  /admin/mpu/list              — list active uploads from Valkey
func RegisterMPUAdminRoutes(muxSrv *http.ServeMux, store MPUStateStore, abortFn MPUAbortFunc, logger *logrus.Logger) {
	muxSrv.HandleFunc("/admin/mpu/abort/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAdminError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
			return
		}
		uploadID := strings.TrimPrefix(r.URL.Path, "/admin/mpu/abort/")
		if uploadID == "" {
			writeAdminError(w, http.StatusBadRequest, "InvalidArgument", "uploadId is required in path")
			return
		}

		ctx := r.Context()
		state, err := store.Get(ctx, uploadID)
		if err != nil {
			if isNotFound(err) {
				writeAdminError(w, http.StatusNotFound, "NoSuchUpload", "upload not found in state store")
			} else {
				logger.WithError(err).WithField("uploadID", uploadID).Error("admin/mpu/abort: failed to get state")
				writeAdminError(w, http.StatusInternalServerError, "InternalError", "failed to retrieve upload state")
			}
			return
		}

		// Best-effort backend abort before cleaning state.
		if abortFn != nil {
			if abortErr := abortFn(ctx, state.Bucket, state.Key, uploadID); abortErr != nil {
				logger.WithError(abortErr).WithFields(logrus.Fields{
					"uploadID": uploadID,
					"bucket":   state.Bucket,
					"key":      state.Key,
				}).Warn("admin/mpu/abort: backend abort failed; deleting state anyway")
			}
		}

		if delErr := store.Delete(ctx, uploadID); delErr != nil {
			logger.WithError(delErr).WithField("uploadID", uploadID).Error("admin/mpu/abort: failed to delete state")
			writeAdminError(w, http.StatusInternalServerError, "InternalError", "failed to delete upload state")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":    "aborted",
			"upload_id": uploadID,
			"bucket":    state.Bucket,
			"key":       state.Key,
		})
	})

	muxSrv.HandleFunc("/admin/mpu/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAdminError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "GET required")
			return
		}

		ctx := r.Context()
		states, err := store.List(ctx)
		if err != nil {
			logger.WithError(err).Error("admin/mpu/list: failed to scan state store")
			writeAdminError(w, http.StatusInternalServerError, "InternalError", "failed to list active uploads")
			return
		}
		if states == nil {
			states = []mpu.UploadState{}
		}

		resp := map[string]interface{}{
			"active_uploads": states,
			"count":          len(states),
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return err == mpu.ErrUploadNotFound
}

