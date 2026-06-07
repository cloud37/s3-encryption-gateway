package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
)

func runInspect() {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	configPath, logLevel, outputFormat := parseSharedFlags(fs, os.Args[2:])

	if fs.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage: s3eg-cli inspect <bucket> <key> [flags]\n")
		fs.PrintDefaults()
		os.Exit(1)
	}
	bucket := fs.Arg(0)
	key := fs.Arg(1)

	logger := newLogger(logLevel, outputFormat)
	client := buildAuditClient(configPath, logger)
	ctx := signalContext()

	report, err := audit.Inspect(ctx, client, bucket, key)
	if err != nil {
		logger.Error("inspect failed", "error", err)
		os.Exit(3)
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
}
