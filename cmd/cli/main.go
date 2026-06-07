// Command s3eg-cli is the gateway-aware read-only audit tool for
// inspecting encryption envelopes on S3 objects managed by the
// s3-encryption-gateway.
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

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subCmd := os.Args[1]

	switch subCmd {
	case "inspect":
		runInspect()
	case "verify-key":
		runVerifyKey()
	case "list-algorithm":
		runListAlgorithm()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "s3eg-cli: unknown sub-command %q\n", subCmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `s3eg-cli — gateway-aware read-only audit tool

Usage:
  s3eg-cli inspect       <bucket> <key>             [--config F] [--log-level L] [--output text|json]
  s3eg-cli verify-key    <bucket> <key>             [--key-version N] [--config F] [--log-level L] [--output text|json]
  s3eg-cli list-algorithm <bucket>                  [--prefix P] [--workers N] [--config F] [--log-level L] [--output text|json]
  s3eg-cli help

Sub-commands:
  inspect          Display the full encryption envelope for an object
  verify-key       Compare recorded key version against a requested version
  list-algorithm   Scan objects and report algorithm/class distribution

Flags:
  --config         Path to gateway config file (default: gateway.yaml)
  --log-level      Log level: debug, info, warn, error (default: info)
  --output         Output format: text or json (default: text)
  --key-version    Requested key version (verify-key only)
  --prefix         Object prefix filter (list-algorithm only)
  --workers        Concurrent workers (list-algorithm only, default: 4)
`)
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

func buildAuditClient(configPath string, logger *slog.Logger) audit.AuditClient {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	client, err := s3.NewClient(&cfg.Backend)
	if err != nil {
		logger.Error("failed to create S3 client", "error", err)
		os.Exit(1)
	}

	return client
}

func parseSharedFlags(fs *flag.FlagSet, args []string) (configPath, logLevel, outputFormat string) {
	configPath = *fs.String("config", "gateway.yaml", "gateway config file")
	logLevel = *fs.String("log-level", "info", "log level: debug, info, warn, error")
	outputFormat = *fs.String("output", "text", "output format: text or json")
	_ = fs.Parse(args)
	return
}

func signalContext() context.Context {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	_ = cancel // keep the compiler happy; cancel is called implicitly when ctx expires
	return ctx
}
