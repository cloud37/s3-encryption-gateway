package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
)

func runVerifyKey() {
	fs := flag.NewFlagSet("verify-key", flag.ExitOnError)
	configPath, logLevel, outputFormat := parseSharedFlags(fs, os.Args[2:])
	keyVersionStr := fs.String("key-version", "", "requested key version to verify against")

	if fs.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage: s3eg-cli verify-key <bucket> <key> [--key-version N] [flags]\n")
		fs.PrintDefaults()
		os.Exit(1)
	}
	bucket := fs.Arg(0)
	key := fs.Arg(1)

	logger := newLogger(logLevel, outputFormat)
	client := buildAuditClient(configPath, logger)
	ctx := signalContext()

	var wantVersion *int
	if *keyVersionStr != "" {
		v, err := strconv.Atoi(*keyVersionStr)
		if err != nil {
			logger.Error("invalid key-version value", "value", *keyVersionStr, "error", err)
			os.Exit(1)
		}
		wantVersion = &v
	}

	report, err := audit.VerifyKey(ctx, client, bucket, key, wantVersion)
	if err != nil {
		logger.Error("verify-key failed", "error", err)
		errStr := err.Error()
		if strings.Contains(errStr, "NoSuchKey") || strings.Contains(errStr, "not found") {
			os.Exit(3)
		}
		os.Exit(1)
	}

	switch outputFormat {
	case "json":
		if err := report.WriteJSON(os.Stdout); err != nil {
			logger.Error("failed to write JSON output", "error", err)
			os.Exit(1)
		}
	default:
		report.WriteText(os.Stdout)
	}

	if !report.Match {
		os.Exit(4)
	}
}
