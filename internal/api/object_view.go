package api

import "github.com/cloud37/s3-encryption-gateway/internal/crypto"

// objectView is the normalized metadata and format classification used by
// object handlers. It deliberately performs no backend I/O.
type objectView struct {
	Bucket, Key string
	VersionID   *string
	Raw         map[string]string
	Expanded    map[string]string
	Class       crypto.ObjectClass
}

func (h *Handler) loadObjectView(bucket, key string, versionID *string, raw map[string]string) (*objectView, error) {
	expanded, err := h.expandMetadataForAPI(bucket, raw)
	if err != nil {
		return nil, err
	}
	class, err := crypto.ClassifyObject(key, expanded)
	if err != nil {
		return nil, err
	}
	return &objectView{Bucket: bucket, Key: key, VersionID: versionID, Raw: raw, Expanded: expanded, Class: class}, nil
}

func setEncryptedMPUMarker(metadata map[string]string, marker string) {
	metadata[crypto.MetaMPUEncrypted] = marker
}
