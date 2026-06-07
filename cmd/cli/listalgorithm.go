package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
)

func runListAlgorithm() {
	fs := flag.NewFlagSet("list-algorithm", flag.ExitOnError)
	configPath, logLevel, outputFormat := parseSharedFlags(fs, os.Args[2:])
	prefix := fs.String("prefix", "", "object prefix filter")
	workers := fs.Int("workers", 4, "concurrent workers")

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: s3eg-cli list-algorithm <bucket> [--prefix P] [--workers N] [flags]\n")
		fs.PrintDefaults()
		os.Exit(1)
	}
	bucket := fs.Arg(0)

	logger := newLogger(logLevel, outputFormat)
	client := buildAuditClient(configPath, logger)
	ctx := signalContext()

	report, err := audit.ListAlgorithm(ctx, client, bucket, *prefix, *workers)
	if err != nil {
		logger.Error("list-algorithm failed", "error", err)
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
}
