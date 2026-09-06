.PHONY: build test lint clean embed-engine e2e fuzz bench coverage-smoke

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
GO_DIR := go
PY_DIR := python
BIN_DIR := bin
PYTHON ?= python3
EMBED_DIR := $(GO_DIR)/internal/embedded/engine

# embed-engine resets the embed directory to a placeholder. As of
# TASK-118 the Go binary no longer bundles the Python engine — secrets
# (TASK-115) and semgrep (TASK-116) are native Go, and the auth /
# injection / deps Python checks are opt-in via `--python-engine`,
# requiring the user to provide a local python/ tree separately. The
# target stays in `make build`'s prereq chain so a clean repo always
# yields a buildable embed/ tree (the //go:embed directive needs the
# directory to exist with at least one entry).
#
# The pre-TASK-118 copy pipeline lives in version control history at
# commit a48be8b — restore it by un-deleting this target's body if you
# need the embedded path for a private build.
embed-engine:
	@echo "→ Resetting embed dir (Python engine no longer bundled — TASK-118)..."
	@rm -rf $(EMBED_DIR)
	@mkdir -p $(EMBED_DIR)
	@echo "# Fendix Python Engine (no longer bundled — TASK-118)" > $(EMBED_DIR)/.gitkeep
	@echo "✓ Embed dir reset; --python-engine opts in to local python/ tree"

build: embed-engine
	@echo "→ Building Go binary..."
	cd $(GO_DIR) && go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o ../$(BIN_DIR)/fendix ./cmd/fendix/
	@echo "✓ Built: $(BIN_DIR)/fendix"

# Coverage contract smoke, deterministic mode: build the fixture's offline
# snapshot, scan the fixture with --offline and the local binary, assert
# every capability recorded ok. Needs semgrep and python3 on PATH; needs NO
# network. The release workflow runs the same script against the candidate
# image with --network none, then a separate online check that only warns.
coverage-smoke: build
	./bin/fendix db update --source tests/fixtures/coverage-smoke/osv-export.json --output /tmp/fendix-smoke-db.json
	./bin/fendix scan --code tests/fixtures/coverage-smoke --python-engine --offline --offline-db /tmp/fendix-smoke-db.json \
	  --format json --output /tmp/fendix-coverage-smoke.json || true
	scripts/coverage-smoke-check.sh --deterministic /tmp/fendix-coverage-smoke.json

test: test-go test-python

test-go:
	@echo "→ Running Go tests..."
	cd $(GO_DIR) && go test -race ./...

# e2e runs end-to-end tests that build the binary and invoke it as a subprocess.
# Gated behind the `e2e` build tag so normal `go test ./...` skips them.
# See go/internal/e2e/ — every CLI flag should have a regression test here.
e2e: build
	@echo "→ Running e2e tests..."
	cd $(GO_DIR) && go test -tags e2e -count=1 ./internal/e2e/...

# fuzz runs the worker-pool cancellation fuzzer for FUZZTIME (default 30s).
# Native go test fuzzing — no extra deps. The seed corpus is exercised on
# every PR via `go test -race`; this target is for ad-hoc deeper runs.
FUZZTIME ?= 30s
fuzz:
	@echo "→ Fuzzing worker-pool cancellation for $(FUZZTIME)..."
	cd $(GO_DIR) && go test -race -fuzz FuzzWorkerPool_CancelTiming \
		-fuzztime $(FUZZTIME) ./internal/engine/

# bench runs the published performance benchmark suite — scan time, memory,
# and peak goroutine count as a function of endpoint count. Numbers in
# README.md "Performance" come from this target on an Apple M1 (8 cores).
# Override BENCHTIME for a longer (more stable) run.
BENCHTIME ?= 5x
bench:
	@echo "→ Running scan benchmarks (BENCHTIME=$(BENCHTIME))..."
	cd $(GO_DIR) && go test -run '^$$' -bench BenchmarkScan -benchmem \
		-benchtime $(BENCHTIME) ./internal/engine/

# benchmark — end-to-end scan against a deliberately-vulnerable target
# app running in Docker. Captures findings + scan duration into a
# timestamped results dir under bench-results/. Numbers in
# docs/benchmarks.md come from this target. Requires Docker, jq, curl,
# and fendix on PATH (or set FENDIX_BIN). See scripts/benchmark/.
benchmark:
	@echo "→ Running juice-shop benchmark..."
	@bash scripts/benchmark/run-juice-shop.sh

# heavy-eval — Track 4 of docs/accuracy.md. Runs fendix against a
# multi-stage labeled corpus + real-world repos + DAST targets + a
# perf profile. Full sweep takes ~30–60 min (DAST images + perf
# repeats are the long pole). See scripts/heavy-eval/ for stage
# definitions and labels.
HEAVY_EVAL_BIN := $(BIN_DIR)/fendix
heavy-eval: build
	@echo "→ Running heavy-eval (all stages, ~30–60 min)..."
	$(PYTHON) scripts/heavy-eval/run.py --binary $(HEAVY_EVAL_BIN) --python-engine --all

# heavy-eval-fast — SAST stages only (4a–4d). ~5 min wall-clock.
# No docker, no perf sweep. Use for CI smoke runs.
heavy-eval-fast: build
	@echo "→ Running heavy-eval (SAST stages only, ~5 min)..."
	$(PYTHON) scripts/heavy-eval/run.py --binary $(HEAVY_EVAL_BIN) --python-engine --fast

test-python:
	@echo "→ Running Python tests..."
	$(PYTHON) -m pytest $(PY_DIR)/tests/ -v

lint: lint-go lint-python

lint-go:
	@echo "→ Checking Go formatting..."
	@test -z "$$(cd $(GO_DIR) && gofmt -l .)" || \
		(echo "gofmt: files need formatting:" && cd $(GO_DIR) && gofmt -l . && exit 1)
	cd $(GO_DIR) && go vet ./...

lint-python:
	@echo "→ Checking Python formatting..."
	@if command -v ruff >/dev/null 2>&1; then \
		cd $(PY_DIR) && ruff check .; \
	else \
		echo "ruff not installed, skipping"; \
	fi
	@if command -v black >/dev/null 2>&1; then \
		cd $(PY_DIR) && black --check .; \
	else \
		echo "black not installed, skipping"; \
	fi

clean:
	rm -rf $(BIN_DIR)/
	cd $(GO_DIR) && go clean
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@# Clean embedded engine (restore placeholder)
	rm -rf $(EMBED_DIR)
	mkdir -p $(EMBED_DIR)
	echo "# Fendix Python Engine (populated at build time)" > $(EMBED_DIR)/.gitkeep
