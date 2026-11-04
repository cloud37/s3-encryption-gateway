package main

import (
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func backendProviderOption(cfg *config.Config) crypto.Option {
	return crypto.WithMetadataProfile(cfg.Backend.Provider, cfg.Backend.MetadataProfile)
}
