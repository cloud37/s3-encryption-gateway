.PHONY: build build-fips migrate migrate-multiarch test test-fips test-conformance test-conformance-compat test-conformance-local test-conformance-external test-conformance-kms test-load test-load-range test-load-multipart test-load-soak test-load-smoke test-load-spike test-load-high-throughput test-load-minio test-load-garage test-load-rustfs test-load-seaweedfs test-load-prometheus test-load-baseline bench-load-capture test-rotation test-fuzz test-comprehensive test-isolation-check bench-lint bench-micro-baseline bench-macro-minio bench-macro-garage bench-macro-rustfs bench-macro-seaweedfs bench-baseline benchmark-local lint clean run docker-build docker-push docker-build-fips docker-push-fips docker-buildx sbom profile-image coverage-gate coverage-html coverage-fips mutation-report mutation-report-pkg help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BINARY_NAME := s3-encryption-gateway
IMAGE_NAME ?= cloud37io/s3-encryption-gateway
IMAGE_TAG ?= $(VERSION)

# V0.6-QA-2 — Coverage gate and mutation testing settings
COVERAGE_THRESHOLD ?= 80
MUTATION_THRESHOLD ?= 70
PKG ?= ./internal/config

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
		-o bin/$(BINARY_NAME)-$(VERSION) ./cmd/server

# Build FIPS-compliant binary
build-fips:
	@echo "Building FIPS-compliant $(BINARY_NAME)..."
	@GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -tags=fips \
		-ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
		-o bin/$(BINARY_NAME)-fips-$(VERSION) ./cmd/server

# Build the migration tool binary
migrate:
	@echo "Building s3eg-migrate..."
	@CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
		-o bin/s3eg-migrate-$(VERSION) ./cmd/migrate

# Build multi-arch gateway binaries
build-multiarch:
	@echo "Building $(BINARY_NAME) for multiple architectures..."
	@GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/$(BINARY_NAME)-linux-amd64  ./cmd/server
	@GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/$(BINARY_NAME)-linux-arm64  ./cmd/server
	@GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/server

# Build multi-arch migration binaries
migrate-multiarch:
	@echo "Building s3eg-migrate for multiple architectures..."
	@GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/s3eg-migrate-linux-amd64  ./cmd/migrate
	@GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/s3eg-migrate-linux-arm64  ./cmd/migrate
	@GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/s3eg-migrate-darwin-arm64 ./cmd/migrate

# Run tests
test:
	@echo "Running tests..."
	@go test -count=1 -v -race -coverprofile=coverage.out ./...

# Run tests with FIPS build tag
test-fips:
	@echo "Running tests with FIPS build tag..."
	@GOFIPS140=v1.0.0 go test -count=1 -v -race -tags=fips ./...

# ── Tier-2 conformance targets (require Docker via Testcontainers) ──────────
#
# test-conformance         All registered providers (local always, external when
#                          credentials are set).
# test-conformance-local   Local providers only (MinIO + Garage + RustFS +
#                          SeaweedFS); skips external.
# test-conformance-external External providers whose credential env vars are set;
#                            local providers skipped.
#
# Local provider skip env vars:
#   GATEWAY_TEST_SKIP_MINIO=1       skip MinIO
#   GATEWAY_TEST_SKIP_GARAGE=1      skip Garage
#   GATEWAY_TEST_SKIP_RUSTFS=1      skip RustFS
#   GATEWAY_TEST_SKIP_SEAWEEDFS=1   skip SeaweedFS

test-conformance:
	@echo "Running conformance tests (all registered providers)..."
	@go test -tags=conformance -count=1 -race -v ./test/conformance/...

test-conformance-local:
	@echo "Running conformance tests (local providers only: MinIO + Garage + RustFS + SeaweedFS)..."
	@GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -count=1 -tags=conformance -race -v -timeout 30m ./test/conformance/...

test-conformance-external:
	@echo "Running conformance tests (external providers with credentials)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 \
		go test -count=1 -tags=conformance -race -v ./test/conformance/...

# V1.0-COMPAT-1 — SDK/Tool compatibility smoke tests (require Docker).
# Runs against all local providers (MinIO, Garage, RustFS, SeaweedFS).
test-conformance-compat:
	@echo "Running SDK/tool compatibility smoke tests (local providers)..."
	@GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -count=1 -tags=conformance -race -v -timeout 30m \
		-run 'TestConformance/.*/Compat_' ./test/conformance/...

# KMS integration conformance test — starts a Cosmian KMS container alongside
# the S3 backend and exercises the full DEK wrap/unwrap path.
# Uses MinIO as the S3 backend (fastest signal); set GATEWAY_TEST_SKIP_COSMIAN=1
# to skip the KMS container if the image is unavailable.
test-conformance-kms:
	@echo "Running KMS integration conformance tests (MinIO + Cosmian KMS)..."
	@GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		go test -count=1 -tags=conformance -race -v \
		-run 'TestConformance/.*/KMS_' ./test/conformance/...

# Mechanical enforcement of the Docker-only deployment model.
test-isolation-check:
	@bash scripts/test-isolation.sh

# ── Tier-2 load tests (in-process, Docker via Testcontainers) ─────────────────
#
# All load targets run the same test functions in test/conformance/load_test.go
# using the in-process harness (MinIO via Testcontainers, no pre-running
# gateway or backend required).  Scale is controlled by environment variables:
#
#   SOAK_WORKERS     number of concurrent worker goroutines
#   SOAK_DURATION    test duration (e.g. "60s", "5m")
#   SOAK_QPS         requests per second per worker
#   SOAK_OBJECT_SIZE object size in bytes
#   SOAK_CHUNK_SIZE  encryption chunk size in bytes
#   SOAK_PART_SIZE   multipart part size in bytes (≥ 5242880)
#
# CI defaults (when env vars are unset): 3 workers · 5 s · 10 qps · 100 KiB
# Soak defaults:                        10 workers · 60 s · 25 qps · 50 MiB
#
# test-load            Fast CI gate: both load tests, small scale.
# test-load-range      Range-read concurrency only (CI scale).
# test-load-multipart  Multipart upload concurrency only (CI scale).
# test-load-soak       Full-scale soak: both tests, large objects, long run.
# test-load-minio      Soak: MinIO provider only (skip Garage).
# test-load-garage     Soak: Garage provider only (skip MinIO).

SOAK_ENV = \
	SOAK_WORKERS=10 \
	SOAK_DURATION=60s \
	SOAK_QPS=25 \
	SOAK_OBJECT_SIZE=52428800 \
	SOAK_PART_SIZE=10485760

SMOKE_ENV = \
	SOAK_WORKERS=3 \
	SOAK_DURATION=10s \
	SOAK_QPS=10 \
	SOAK_OBJECT_SIZE=102400

SPIKE_ENV = \
	SOAK_WORKERS=50 \
	SOAK_DURATION=60s \
	SOAK_QPS=50 \
	SOAK_OBJECT_SIZE=102400

HIGH_THROUGHPUT_ENV = \
	SOAK_WORKERS=5 \
	SOAK_DURATION=120s \
	SOAK_QPS=5 \
	SOAK_OBJECT_SIZE=52428800 \
	SOAK_PART_SIZE=10485760

test-load-range:
	@echo "Running range load tests (conformance suite, local providers, CI scale)..."
	@go test -count=1 -tags=conformance -race -v -timeout 120s \
		-run 'TestConformance/.*/Load_RangeRead' ./test/conformance/...

test-load-multipart:
	@echo "Running multipart load tests (conformance suite, local providers, CI scale)..."
	@go test -count=1 -tags=conformance -race -v -timeout 120s \
		-run 'TestConformance/.*/Load_Multipart' ./test/conformance/...

test-load: test-load-range test-load-multipart

# Full-scale soak: same tests, soak-scale parameters, no timeout limit.
test-load-soak:
	@echo "Running full-scale soak load tests (all local providers, 60 s, 10 workers, 50 MiB objects)..."
	@$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/...

# Soak MinIO only.
test-load-minio:
	@echo "Running full-scale soak load tests (MinIO only)..."
	@GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/minio/Load_' ./test/conformance/...

# Soak Garage only.
test-load-garage:
	@echo "Running full-scale soak load tests (Garage only)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/garage/Load_' ./test/conformance/...

# Soak RustFS only.
test-load-rustfs:
	@echo "Running full-scale soak load tests (RustFS only)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_SEAWEEDFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/rustfs/Load_' ./test/conformance/...

# Soak SeaweedFS only.
test-load-seaweedfs:
	@echo "Running full-scale soak load tests (SeaweedFS only)..."
	@GATEWAY_TEST_SKIP_MINIO=1 GATEWAY_TEST_SKIP_GARAGE=1 GATEWAY_TEST_SKIP_RUSTFS=1 GATEWAY_TEST_SKIP_EXTERNAL=1 \
		$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/seaweedfs/Load_' ./test/conformance/...

# Soak with custom duration override.
# Usage: make test-load-prometheus SOAK_DURATION=5m
test-load-prometheus:
	@echo "Running soak load tests (custom duration; set SOAK_DURATION to override)..."
	@$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/...

# Update baselines by running soak and capturing output.
# The soak tests log throughput/latency data; redirect to a file for tracking.
test-load-baseline:
	@echo "Running soak load tests for baseline capture..."
	@$(SOAK_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/.*/Load_' ./test/conformance/... \
		2>&1 | tee testdata/baselines/soak_$(shell date +%Y%m%d_%H%M%S).log
	@echo "Baseline log written to testdata/baselines/"

# ── V1.0-PERF-1 Named load profile targets ──────────────────────────────────
#
# Three named profiles (smoke, spike, high-throughput) supplement the existing
# soak profile (test-load-soak).  Each applies a different env-var preset:
#
#   smoke          3 workers, 10s, 10 QPS, 100 KiB objects  — quick CI gate
#   spike         50 workers, 60s, 50 QPS, 100 KiB objects  — HPA trigger regime
#   high-throughput 10 workers, 300s, 10 QPS, 500 MiB objects — bandwidth-bound
#
# bench-load-capture runs all four profiles (smoke + soak + spike +
# high-throughput) sequentially, writing NDJSON output into
# docs/perf/v1.0-perf-1/.

test-load-smoke:
	@echo "Running smoke load profile (fast CI gate)..."
	@$(SMOKE_ENV) go test -count=1 -tags=conformance -v -timeout 120s \
		-run 'TestConformance/minio/Load_' ./test/conformance/...

test-load-spike:
	@echo "Running spike load profile (50 workers, 60s, 100 KiB objects)..."
	@$(SPIKE_ENV) go test -count=1 -tags=conformance -v -timeout 300s \
		-run 'TestConformance/minio/Load_' ./test/conformance/...

test-load-high-throughput:
	@echo "Running high-throughput load profile (500 MiB objects)..."
	@$(HIGH_THROUGHPUT_ENV) go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/minio/Load_' ./test/conformance/...

bench-load-capture:
	@mkdir -p docs/perf/v1.0-perf-1
	@$(SMOKE_ENV) SOAK_JSON_OUT=$(PWD)/docs/perf/v1.0-perf-1/smoke.ndjson \
		go test -count=1 -tags=conformance -v -timeout 120s \
		-run 'TestConformance/minio/Load_' ./test/conformance/...
	@$(SOAK_ENV) SOAK_JSON_OUT=$(PWD)/docs/perf/v1.0-perf-1/soak.ndjson \
		go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/minio/Load_' ./test/conformance/...
	@$(SPIKE_ENV) SOAK_JSON_OUT=$(PWD)/docs/perf/v1.0-perf-1/spike.ndjson \
		go test -count=1 -tags=conformance -v -timeout 300s \
		-run 'TestConformance/minio/Load_' ./test/conformance/...
	@$(HIGH_THROUGHPUT_ENV) SOAK_JSON_OUT=$(PWD)/docs/perf/v1.0-perf-1/high-throughput.ndjson \
		go test -count=1 -tags=conformance -v -timeout 0 \
		-run 'TestConformance/minio/Load_' ./test/conformance/...
	@echo "Load profiles captured to docs/perf/v1.0-perf-1/"

# ── V0.6-QA-1 performance baseline targets ──────────────────────────────────
#
# bench-lint           Grep-level check that every Benchmark* includes
#                      b.ReportAllocs() and either b.SetBytes() or a
#                      documented exemption comment.  Runs in PR CI.
# bench-micro-baseline Produces docs/perf/v0.6-qa-1/micro-baseline.txt via
#                      the canonical go test -bench invocation from
#                      docs/plans/V0.6-QA-1-plan.md §3.1.
# bench-macro-<prov>   Runs the soak harness against one local provider and
#                      writes docs/perf/v0.6-qa-1/macro-<provider>.json.
# bench-baseline       Runs micro + all four macros serially; used
#                      on-demand and by the nightly `performance-baseline`
#                      workflow. Expect ~30-40 min wall-clock.

bench-lint:
	@bash scripts/bench-lint.sh

bench-micro-baseline:
	@bash scripts/bench-baseline.sh docs/perf/v0.6-qa-1/micro-baseline.txt

bench-macro-minio:
	@bash scripts/bench-macro.sh minio

bench-macro-garage:
	@bash scripts/bench-macro.sh garage

bench-macro-rustfs:
	@bash scripts/bench-macro.sh rustfs

bench-macro-seaweedfs:
	@bash scripts/bench-macro.sh seaweedfs

bench-baseline: bench-micro-baseline bench-macro-minio bench-macro-garage bench-macro-rustfs bench-macro-seaweedfs
	@echo "bench-baseline: complete. Artefacts under docs/perf/v0.6-qa-1/."

# benchmark-local — full local encryption benchmark matrix.
#
# Runs all 4 local providers (MinIO, Garage, RustFS, SeaweedFS) × 18 encryption
# configurations:
#  Chunked PutGet (5): PBKDF2 600k, PBKDF2 100k, Argon2id, AES KEK, RSA KEK
#  Encrypted MPU  (5): AES KEK, PBKDF2 600k, PBKDF2 100k, Argon2id, RSA KEK
#  Ranged GET      (5): AES KEK, PBKDF2 600k, PBKDF2 100k, Argon2id, RSA KEK
#  Cosmian KMIP KMS(3): Chunked, Encrypted MPU, Ranged GET (skipped if
#                       GATEWAY_TEST_SKIP_COSMIAN=1)
#
# Tuning via environment variables:
#   BENCH_LOCAL_WORKERS=8            goroutines per config
#   BENCH_LOCAL_DURATION=30s         test duration per config
#   BENCH_LOCAL_OBJECT_SIZE=1048576  single-object size (bytes)
#   BENCH_LOCAL_MPU_SIZE=5242880    per-part MPU size (bytes)
#   BENCH_LOCAL_JSON_OUT=results.ndjson  NDJSON output file (optional;
#                                         relative paths are resolved from
#                                         the repository root)
#   GATEWAY_TEST_SKIP_COSMIAN=1     skip Cosmian KMS-backed configs
#
# NOT run in CI (requires Docker + local provider containers).
benchmark-local:
	@echo "Starting local benchmark suite (all providers × all encryption configs)..."
	@if [ -n "$$BENCH_LOCAL_JSON_OUT" ]; then \
		export BENCH_LOCAL_JSON_OUT=$$(realpath "$$BENCH_LOCAL_JSON_OUT" 2>/dev/null || readlink -f "$$BENCH_LOCAL_JSON_OUT"); \
		echo "  output file: $$BENCH_LOCAL_JSON_OUT"; \
	fi; \
	go test -count=1 -tags=conformance,benchmark_local -v -timeout 0 \
		-run 'TestBenchmarkLocal' ./test/conformance/...

# Run key rotation conformance tests (tier-2, all registered providers).
test-rotation:
	@echo "Running key rotation conformance tests (all registered providers)..."
	@go test -count=1 -tags=conformance -race -v -run 'TestConformance/.*/Rotation_' ./test/conformance/...

# Run fuzz tests (as regression tests)
test-fuzz:
	@echo "Running fuzz tests (regression mode)..."
	@go test -count=1 -v ./internal/crypto -run=Fuzz -fuzztime=1s

# Run comprehensive test suite.
# Requires only Docker (no docker-compose up, no pre-existing binaries).
test-comprehensive:
	@echo "Running comprehensive test suite..."
	@echo "1. Running tier-1 unit tests..."
	@go test -count=1 -race -short ./...
	@echo "2. Running conformance tests (local providers via Testcontainers)..."
	@$(MAKE) test-conformance-local
	@echo "3. Checking test isolation (Docker-only model)..."
	@$(MAKE) test-isolation-check

# Run tests with coverage
test-coverage: test
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# V1.0-SEC-18 — lint gate: no fmt.Printf in debug.Enabled blocks
lint-debug-print:
	@echo "Checking for forbidden fmt.Printf in debug blocks..."
	@bash scripts/debug-lint.sh

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

# Run the server locally
run: build
	@echo "Running server..."
	@./bin/$(BINARY_NAME)

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

# Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	@docker push $(IMAGE_NAME):$(IMAGE_TAG)

# Build a symbolicated (non-stripped) image for pprof profiling.
# V0.6-OBS-1: use when you need full function names in pprof flamegraphs.
# The image is tagged with ":profile" suffix to distinguish it from production.
# Usage: make profile-image && go tool pprof -http=:0 http://localhost:8081/admin/debug/pprof/heap
profile-image:
	@echo "Building profile (non-stripped symbols) image for pprof..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg STRIP_SYMBOLS=false \
		-t $(IMAGE_NAME):$(IMAGE_TAG)-profile .
	@echo "Profile image built: $(IMAGE_NAME):$(IMAGE_TAG)-profile"
	@echo "Run with admin.profiling.enabled=true and enable pprof via config."

# Build FIPS Docker image
docker-build-fips:
	@echo "Building FIPS Docker image..."
	@docker build -f Dockerfile.fips \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_NAME):$(IMAGE_TAG)-fips .

# Push FIPS Docker image
docker-push-fips:
	@echo "Pushing FIPS Docker image..."
	@docker push $(IMAGE_NAME):$(IMAGE_TAG)-fips

# docker-buildx — build multi-arch image locally (requires Docker buildx)
# Usage: make docker-buildx VERSION=1.0.0
docker-buildx:
	@echo "Building multi-arch Docker image (linux/amd64, linux/arm64)..."
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		--load .
	@echo "Multi-arch image built: $(IMAGE_NAME):$(IMAGE_TAG)"

# sbom — generate SPDX-JSON SBOM for the local Docker image using syft
# Requires: syft installed (go install github.com/anchore/syft/cmd/syft@latest)
# Usage: make sbom IMAGE_NAME=cloud37io/s3-encryption-gateway IMAGE_TAG=latest
sbom:
	@echo "Generating SBOM for $(IMAGE_NAME):$(IMAGE_TAG)..."
	@syft $(IMAGE_NAME):$(IMAGE_TAG) -o spdx-json=sbom.spdx.json
	@echo "SBOM written to sbom.spdx.json"

# Run all tests including integration
docker-all: docker-build docker-push docker-build-fips docker-push-fips

# Run security scan
security-scan:
	@echo "Running security scan..."
	@govulncheck ./...
	@echo "Running gosec..."
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude=G104 -severity high ./...

# gosec — run static analysis security scan
gosec:
	@echo "Running gosec static analysis..."
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude=G104 -severity high ./...

# trivy-scan — scan the local Docker image for vulnerabilities
# Usage: make trivy-scan IMAGE_NAME=cloud37io/s3-encryption-gateway IMAGE_TAG=latest
trivy-scan:
	@echo "Running Trivy container image scan..."
	@docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image \
		--severity HIGH,CRITICAL \
		--ignore-unfixed \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install github.com/anchore/syft/cmd/syft@latest

# Generate test coverage report (legacy target)
coverage:
	@go test -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

# ── V0.6-QA-2 Coverage Gate targets ─────────────────────────────────────────

# coverage-gate — Enforce ≥COVERAGE_THRESHOLD% project-wide statement coverage.
# Uses scripts/coverage-gate.sh; excludes packages in scripts/coverage-exclude.txt.
# Override threshold: make coverage-gate COVERAGE_THRESHOLD=85
coverage-gate:
	@COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD) bash scripts/coverage-gate.sh $(COVERAGE_THRESHOLD)

# coverage-html — Open an HTML coverage report in the browser.
# Requires coverage.out to exist (run make coverage-gate first).
coverage-html: coverage-gate
	@go tool cover -html=coverage.out -o coverage.html
	@echo "HTML report: coverage.html"
	@if command -v xdg-open >/dev/null 2>&1; then xdg-open coverage.html; \
	elif command -v open >/dev/null 2>&1; then open coverage.html; \
	else echo "Open coverage.html in your browser"; fi

# coverage-fips — Run coverage gate with FIPS build tag.
# Both the default profile and this FIPS profile must meet COVERAGE_THRESHOLD.
coverage-fips:
	@COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD) \
	COVERAGE_TAGS=fips \
	COVERAGE_PROFILE=coverage-fips.out \
	FIPS_COVERAGE_PROFILE=coverage-fips.out \
	bash scripts/coverage-gate.sh $(COVERAGE_THRESHOLD)

# ── V0.6-QA-2 Mutation Testing targets ───────────────────────────────────────

# mutation-report — Run Gremlins on all four in-scope packages.
# Requires gremlins to be installed: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
mutation-report:
	@bash scripts/mutation-report.sh

# mutation-report-pkg — Run Gremlins on a single package.
# Usage: make mutation-report-pkg PKG=./internal/config
mutation-report-pkg:
	@bash scripts/mutation-report.sh $(PKG)

# Help target
help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  build-multiarch    - Build the binary for linux/amd64, linux/arm64, darwin/arm64"
	@echo "  build-fips         - Build FIPS-compliant binary"
	@echo "  migrate            - Build the s3eg-migrate tool"
	@echo "  migrate-multiarch  - Build s3eg-migrate for linux/amd64, linux/arm64, darwin/arm64"
	@echo "  test               - Run tier-1 unit tests (-race)"
	@echo "  test-fips          - Run tests with FIPS build tag"
	@echo "  test-fuzz          - Run fuzz tests (regression mode)"
	@echo "  test-conformance   - Run tier-2 conformance tests (all providers; requires Docker)"
	@echo "  test-conformance-compat - Run SDK/tool compatibility smoke tests (V1.0-COMPAT-1)"
	@echo "  test-conformance-local  - Conformance: local providers (MinIO + Garage + RustFS + SeaweedFS)"
	@echo "  test-conformance-external - Conformance: external providers with credentials"
	@echo "  test-conformance-kms     - Conformance: KMS envelope encryption (MinIO + Cosmian KMS)"
	@echo "  test-isolation-check    - Check test/ does not reference docker-compose / hard-coded ports"
	@echo "  test-load          - CI load gate: range + multipart, small scale (5 s, 100 KiB)"
	@echo "  test-load-range    - CI load gate: range-read concurrency only"
	@echo "  test-load-multipart- CI load gate: multipart upload concurrency only"
	@echo "  test-load-soak     - Full soak: both tests, 60 s, 10 workers, 50 MiB objects"
	@echo "  test-load-minio    - Full soak: MinIO provider only"
	@echo "  test-load-garage   - Full soak: Garage provider only"
	@echo "  test-load-rustfs   - Full soak: RustFS provider only"
	@echo "  test-load-seaweedfs- Full soak: SeaweedFS provider only"
	@echo "  test-load-baseline - Soak run with log capture to testdata/baselines/"
	@echo "  test-load-prometheus-Soak run with custom duration (set SOAK_DURATION)"
	@echo "  bench-lint         - Check every Benchmark* has ReportAllocs() + SetBytes() (V0.6-QA-1)"
	@echo "  bench-micro-baseline - Run micro benchmarks, write docs/perf/v0.6-qa-1/micro-baseline.txt"
	@echo "  bench-macro-<prov>   - Run soak on one provider, write macro-<prov>.json (minio|garage|rustfs|seaweedfs)"
	@echo "  bench-baseline     - Run micro + all four macros (full V0.6-QA-1 baseline)"
	@echo "  benchmark-local    - Full local encryption benchmark matrix (4 providers × 18 configs)"
	@echo "  test-rotation      - Run key rotation conformance tests (tier-2, all providers)"
	@echo "  test-comprehensive - Run comprehensive test suite (tier-1 + local conformance + isolation check)"
	@echo "  test-coverage      - Run tests with HTML coverage report"
	@echo "  lint               - Run linter"
	@echo "  fmt                - Format code"
	@echo "  clean              - Clean build artifacts"
	@echo "  run                - Build and run the server"
	@echo "  docker-build       - Build Docker image"
	@echo "  docker-push        - Push Docker image"
	@echo "  docker-build-fips  - Build FIPS Docker image"
	@echo "  docker-push-fips   - Push FIPS Docker image"
	@echo "  docker-buildx      - Build multi-arch Docker image via buildx (requires docker buildx)"
	@echo "  sbom               - Generate SPDX-JSON SBOM via syft (requires syft)"
	@echo "  profile-image      - Build non-stripped image for pprof (V0.6-OBS-1)"
	@echo "  security-scan      - Run govulncheck + gosec security scan"
	@echo "  gosec              - Run gosec static analysis security scan"
	@echo "  trivy-scan         - Run Trivy container image scan (requires IMAGE_NAME + IMAGE_TAG)"
	@echo "  install-tools      - Install development tools"
	@echo "  coverage           - Generate test coverage report (legacy)"
	@echo "  coverage-gate      - Enforce ≥COVERAGE_THRESHOLD% coverage (default: 80) (V0.6-QA-2)"
	@echo "  coverage-html      - Generate and open HTML coverage report (V0.6-QA-2)"
	@echo "  coverage-fips      - Run coverage gate with -tags=fips (V0.6-QA-2)"
	@echo "  mutation-report    - Run Gremlins mutation testing on all in-scope packages (V0.6-QA-2)"
	@echo "  mutation-report-pkg PKG=./internal/config - Mutation testing on a single package (V0.6-QA-2)"
	@echo "  help               - Show this help message"
