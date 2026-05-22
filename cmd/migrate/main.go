package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/migrate"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

func main() {
	// Sub-command dispatch — must happen before flag.Parse so that flags
	// defined for the default migrate command do not conflict.
	args := os.Args[1:]
	for i, a := range args {
		if a == "backfill-legacy-no-aad" {
			// Remove the sub-command token from os.Args so flag.Parse works
			// on the remaining flags.
			os.Args = append(os.Args[:i+1], os.Args[i+2:]...)
			runBackfill()
			return
		}
	}
	runMigrate()
}

func runMigrate() {
	var (
		configPath     = flag.String("config", "gateway.yaml", "gateway config file")
		gatewayVersion = flag.String("gateway-version", "", "REQUIRED: version of the currently-running gateway (0.6.4 or 0.7.0)")
		sourceKeyVer   = flag.Int("source-key-version", 0, "optional: force old KEK version for source decrypt")
		targetKeyVer   = flag.Int("target-key-version", 0, "optional: force new KEK version for target encrypt")
		bucket         = flag.String("bucket", "", "target S3 bucket")
		prefix         = flag.String("prefix", "", "optional: object prefix")
		workers        = flag.Int("workers", 4, "number of parallel workers")
		dryRun         = flag.Bool("dry-run", false, "scan only; no writes")
		verifyFlag     = flag.Bool("verify", true, "enable post-write hash verification")
		noVerify       = flag.Bool("no-verify", false, "disable verification")
		stateFile      = flag.String("state-file", "", "resume state file")
		migrationClass = flag.String("migration-class", "all", "which classes to migrate (all, sec2, sec4, sec27)")
		verifyDelay    = flag.Duration("verify-delay", 0, "pause before verify read")
		logLevel       = flag.String("log-level", "info", "log level: debug, info, warn, error")
		outputFormat   = flag.String("output", "text", "output format: text or json")
	)
	flag.Parse()

	logger := newLogger(*logLevel, *outputFormat)

	if *gatewayVersion == "" {
		logger.Error("--gateway-version is required")
		flag.Usage()
		os.Exit(1)
	}
	if *bucket == "" {
		logger.Error("--bucket is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg, s3Client, sourceEngine, targetEngine := mustBuildDeps(*configPath, *sourceKeyVer, *targetKeyVer, logger)
	_ = cfg

	sf := *stateFile
	if sf == "" {
		prefixTag := ""
		if *prefix != "" {
			prefixTag = "-" + sanitizePrefix(*prefix)
		}
		sf = fmt.Sprintf("%s%s-%s-migration.json", *bucket, prefixTag, *gatewayVersion)
	}

	verify := *verifyFlag && !*noVerify

	m := &migrate.Migrator{
		S3Client:       s3Client,
		SourceEngine:   sourceEngine,
		TargetEngine:   targetEngine,
		GatewayVersion: *gatewayVersion,
		Workers:        *workers,
		StateFile:      sf,
		DryRun:         *dryRun,
		Verify:         verify,
		VerifyDelay:    *verifyDelay,
		Filter:         migrate.MigrationClassFilter(*migrationClass),
		Logger:         logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting migration",
		"bucket", *bucket,
		"prefix", *prefix,
		"gateway_version", *gatewayVersion,
		"dry_run", *dryRun,
		"verify", verify,
		"state_file", sf,
	)

	start := time.Now()
	if err := m.Migrate(ctx, *bucket, *prefix); err != nil {
		logger.Error("migration finished with errors", "error", err, "elapsed", time.Since(start))
		os.Exit(2)
	}
	logger.Info("migration finished successfully", "elapsed", time.Since(start))
}

func runBackfill() {
	fs := flag.NewFlagSet("backfill-legacy-no-aad", flag.ExitOnError)
	var (
		configPath     = fs.String("config", "gateway.yaml", "gateway config file")
		gatewayVersion = fs.String("gateway-version", "", "REQUIRED: version of the currently-running gateway (0.6.4 or 0.7.0)")
		bucket         = fs.String("bucket", "", "target S3 bucket")
		prefix         = fs.String("prefix", "", "optional: object prefix")
		workers        = fs.Int("workers", 4, "number of parallel workers (currently informational; backfill is sequential)")
		dryRun         = fs.Bool("dry-run", false, "scan only; print what would be tagged without writing")
		confirmBackfill = fs.Bool("confirm-backfill", false, "REQUIRED: acknowledge that this operation adds metadata markers to objects")
		logLevel       = fs.String("log-level", "info", "log level: debug, info, warn, error")
		outputFormat   = fs.String("output", "text", "output format: text or json")
	)
	_ = fs.Parse(os.Args[1:])

	logger := newLogger(*logLevel, *outputFormat)

	if !*confirmBackfill && !*dryRun {
		logger.Error("backfill-legacy-no-aad requires --confirm-backfill (or --dry-run to preview)")
		os.Exit(1)
	}
	if *gatewayVersion == "" {
		logger.Error("--gateway-version is required")
		fs.Usage()
		os.Exit(1)
	}
	if *bucket == "" {
		logger.Error("--bucket is required")
		fs.Usage()
		os.Exit(1)
	}
	_ = *workers // reserved for future parallel backfill

	_, s3Client, sourceEngine, _ := mustBuildDeps(*configPath, 0, 0, logger)

	m := &migrate.Migrator{
		S3Client:     s3Client,
		SourceEngine: sourceEngine,
		DryRun:       *dryRun,
		Logger:       logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting backfill-legacy-no-aad",
		"bucket", *bucket,
		"prefix", *prefix,
		"dry_run", *dryRun,
	)

	start := time.Now()
	if err := m.BackfillLegacyNoAAD(ctx, *bucket, *prefix); err != nil {
		logger.Error("backfill finished with errors", "error", err, "elapsed", time.Since(start))
		os.Exit(2)
	}
	logger.Info("backfill finished successfully", "elapsed", time.Since(start))
}

// mustBuildDeps loads config and constructs the S3 client and crypto engines.
// It calls os.Exit(1) on any fatal error.
func mustBuildDeps(configPath string, sourceKeyVer, targetKeyVer int, logger *slog.Logger) (*config.Config, migrate.S3Client, crypto.EncryptionEngine, crypto.EncryptionEngine) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	s3Client, err := s3.NewClient(&cfg.Backend)
	if err != nil {
		logger.Error("failed to create S3 client", "error", err)
		os.Exit(1)
	}

	sourceEngine, targetEngine, err := buildEngines(cfg, sourceKeyVer, targetKeyVer)
	if err != nil {
		logger.Error("failed to build engines", "error", err)
		os.Exit(1)
	}

	return cfg, s3Client, sourceEngine, targetEngine
}

func newLogger(level, format string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}

func buildEngines(cfg *config.Config, sourceKeyVer, targetKeyVer int) (crypto.EncryptionEngine, crypto.EncryptionEngine, error) {
	password := cfg.Encryption.Password
	if password == "" && cfg.Encryption.KeyFile != "" {
		data, err := os.ReadFile(cfg.Encryption.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read key file: %w", err)
		}
		password = string(data)
	}
	if password == "" {
		return nil, nil, fmt.Errorf("encryption password not configured")
	}

	// Source and target engines share the same configuration by default.
	// If key versions differ, a key resolver is required — for now both engines
	// are identical and the migration tool assumes the same password/key.
	// TODO: support per-version key resolvers when KMS rotation is used.
	engine, err := crypto.NewEngineWithChunking(
		[]byte(password),
		nil, // compression engine — can be added later
		cfg.Encryption.PreferredAlgorithm,
		cfg.Encryption.SupportedAlgorithms,
		cfg.Encryption.ChunkedMode,
		cfg.Encryption.ChunkSize,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create engine: %w", err)
	}

	_ = sourceKeyVer
	_ = targetKeyVer

	return engine, engine, nil
}

func sanitizePrefix(p string) string {
	p = strings.ReplaceAll(p, "/", "-")
	p = strings.ReplaceAll(p, "\\", "-")
	if len(p) > 20 {
		p = p[:20]
	}
	return p
}
