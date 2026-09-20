# Contributing to Fendix

Thank you for your interest in contributing to Fendix! This guide covers development setup, how to add new security checks, coding standards, and the pull request process.

---

## Development Setup

### Prerequisites

- **Go 1.21+** — for the CLI and black-box scanner
- **Python 3.9+** — for the static analysis engine
- **Make** — build automation

### Getting started

```bash
git clone https://github.com/Fendix-app/Fendix.git
cd fendix

# Build the Go binary
make build

# Install Python test dependencies
pip install -r python/requirements.txt
pip install pytest

# Run all tests
make test

# Verify everything works
./bin/fendix version
```

### Project structure

```
go/                          # Go layer — CLI, HTTP scanner, orchestrator
  cmd/fendix/main.go         # CLI entrypoint (cobra)
  internal/
    scanner/                  # Black-box check implementations
    engine/                   # Orchestrator, correlator, Python spawner
    models/                   # Finding, ScanConfig, severity scoring
    reporters/                # JSON, HTML, SARIF renderers
    embedded/                 # Embedded Python engine (//go:embed)

python/                      # Python layer — static analysis engine
  engine.py                  # Entrypoint: reads stdin, streams findings
  analyzers/                  # Secrets, Semgrep, spec parser, AST, deps
  rules/                      # Custom Semgrep YAML rules
  tests/                      # pytest test suite
```

### Running tests

```bash
# All tests
make test

# Go tests only (with race detector)
cd go && go test -race -v ./...

# Python tests only
cd python && python -m pytest tests/ -v

# Single Go package
cd go && go test -v ./internal/scanner/...

# Single Python test file
cd python && python -m pytest tests/test_secrets.py -v
```

### Linting

```bash
make lint

# Individual linters
cd go && gofmt -l . && go vet ./...
cd python && ruff check . && black --check .
```

---

## How to Add a Security Check

Fendix has two engines. Choose the right one for your check:

| Engine | When to use |
|---|---|
| **Go (black-box)** | You need to send HTTP requests and analyze responses |
| **Python (white-box)** | You need to analyze source code, specs, or dependencies |

### Adding a black-box check (Go)

1. **Create the check file** in `go/internal/scanner/`:

```go
// go/internal/scanner/mycheck.go
package scanner

import (
    "context"
    "github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// CheckMyThing scans for [describe what it checks].
func CheckMyThing(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
    var findings []models.Finding

    // 1. Build and send HTTP request
    resp, err := makeRequest(ctx, cfg, endpoint.FullURL)
    if err != nil {
        return nil // Don't report errors as findings
    }

    // 2. Analyze the response
    if isVulnerable(resp) {
        findings = append(findings, models.Finding{
            Title:      "Descriptive title of the issue",
            Severity:   models.SeverityHigh,
            Source:     models.SourceBlackbox,
            Category:   "mycategory",
            Endpoint:   endpoint.String(),
            Evidence:   "What was observed (truncated if needed)",
            Fix:        "Actionable remediation steps",
            References: []string{"CWE-XXX"},
            Confidence: models.ConfidenceHigh,
        })
    }

    return findings
}
```

2. **Write tests** in `go/internal/scanner/mycheck_test.go`:

```go
func TestCheckMyThing(t *testing.T) {
    tests := []struct {
        name     string
        handler  http.HandlerFunc
        expected int // expected finding count
    }{
        {
            name:     "vulnerable server",
            handler:  func(w http.ResponseWriter, r *http.Request) { /* ... */ },
            expected: 1,
        },
        {
            name:     "safe server",
            handler:  func(w http.ResponseWriter, r *http.Request) { /* ... */ },
            expected: 0,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            srv := httptest.NewServer(tt.handler)
            defer srv.Close()
            // ... test the check against srv.URL
        })
    }
}
```

3. **Register in orchestrator** — add your check to the check list in `go/internal/engine/orchestrator.go`

4. **Document** — create `docs/checks/mycheck.md`

### Adding a white-box check (Python)

> **First check whether it belongs in Python at all.** Secrets detection lives
> in `go/internal/scanner/secrets/` (TASK-115), Semgrep in
> `go/internal/scanner/semgrep/` (TASK-116), and dependency-CVE scanning in
> `go/internal/scanner/deps/`. The Python wrappers for secrets and semgrep were
> deleted in TASK-118. Python (`--python-engine`, opt-in) now carries only the
> AST taint analyzer, the route extractor, the OpenAPI spec parser, and its own
> deps analyzer.

1. **Create the analyzer** in `python/analyzers/`:

```python
# python/analyzers/myanalyzer.py
"""MyAnalyzer — detects [what it detects]."""

from typing import Callable

class MyAnalyzer:
    """Detects [specific vulnerability pattern] in source code."""

    def __init__(self, code_path: str) -> None:
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run analysis and emit findings via emit_fn."""
        # Walk files, analyze, call emit_fn with Finding dicts
        emit_fn({
            "title": "Issue found",
            "severity": "HIGH",
            "source": "whitebox",
            "category": "mycategory",
            "endpoint": "file.py:42",
            "evidence": "what was found",
            "fix": "how to fix it",
            "references": ["CWE-XXX"],
            "confidence": "MEDIUM",
            "line": "file.py:42"
        })
```

2. **Write tests** in `python/tests/test_myanalyzer.py` using pytest fixtures

3. **Register in engine** — add the analyzer to `python/engine.py`

### Adding a Semgrep rule

Add a YAML rule to **`go/internal/scanner/semgrep/rules/`** — the pack the Go
scanner embeds with `//go:embed rules/*.yaml` (see
`go/internal/scanner/semgrep/scanner.go`). Pick the file matching the rule's
category (`auth.yaml`, `crypto.yaml`, `injection.yaml`, `secrets.yaml`), or add
a new `.yaml` there — the embed glob picks up every file in the directory at
build time.

> ⚠️ **`python/rules/` is dead.** It is read by no code: the Python `semgrep`
> wrapper (`python/analyzers/semgrep_runner.py`) was deleted in TASK-118 and
> `python/engine.py` now treats a `semgrep` check request as a no-op. A rule
> added under `python/rules/` will never run. The directory is kept only as
> historical reference metadata (see `docs/MODULE_MAP.md`); do not add to it.

```yaml
rules:
  - id: my-custom-rule
    pattern: dangerous_function($INPUT)
    message: "Potentially unsafe use of dangerous_function"
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-XXX
      category: mycategory
      confidence: MEDIUM        # HIGH | MEDIUM | LOW — required by the rulepack audit
      fendix_severity: HIGH     # CRITICAL | HIGH | MEDIUM | LOW | INFO — required
```

Rules are picked up automatically at build time — no registration needed. Two
things you **must** do in the same commit:

1. Every rule needs `metadata.category`, `metadata.cwe`, `metadata.confidence`
   and `metadata.fendix_severity`. `scanner_rulepack_test.go` fails the build
   otherwise. A rule with `confidence: LOW` may not exceed
   `fendix_severity: MEDIUM` — the orchestrator would silently downgrade it.
2. Bump `rulepackTotalCount` in
   `go/internal/scanner/semgrep/scanner_rulepack_test.go` and the bundled-rule
   count in `README.md` ("Semgrep Rules" row of the white-box table).

If you add a whole new `.yaml` file, also add its name to `rulepackFiles` in
that same test.

---

## Coding Standards

### Go

- **Formatting:** `gofmt` clean at all times
- **Error handling:** All errors wrapped with context: `fmt.Errorf("doing X: %w", err)`
- **Context:** Propagate `context.Context` on all network calls
- **Tests:** Table-driven tests with `t.Run()` and `net/http/httptest`
- **Logging:** `log/slog` for structured logging
- **State:** No global mutable state — pass dependencies explicitly
- **Interfaces:** Define interfaces for all mockable dependencies
- **Comments:** All exported symbols must have godoc comments

### Python

- **Type hints:** All function signatures must have type annotations
- **Docstrings:** All public classes and functions
- **Formatting:** `ruff` + `black`
- **Testing:** `pytest` with fixtures
- **File I/O:** Use context managers (`with` statements)

### Git

- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
- **Branch names:** `feat/description`, `fix/description`
- **No broken builds:** CI must pass before merge

---

## IPC Data Contract

The Go and Python layers communicate via newline-delimited JSON over stdin/stdout. If your change touches this boundary, you **must** update both sides.

### ScanRequest (Go sends to Python stdin)

```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

### Finding (Python streams to Go stdout)

```json
{
  "title": "Hardcoded API key",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "API_KEY = 'sk-live-...'",
  "fix": "Move to environment variable",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

### Stream terminator

```json
{"done": true, "total": 12}
```

---

## Safety Rules (non-negotiable)

1. **Active probes never run without `--enable-active`** — this is a hard gate, not a default
2. **Auth credentials always masked as `[REDACTED]`** in all report output
3. **Python engine crash never crashes the Go binary** — the orchestrator must handle subprocess failures gracefully

---

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Write your code following the standards above
3. Add tests — we don't merge without tests
4. Run `make test && make lint` locally
5. Open a PR with a clear description of what and why
6. Wait for CI to pass and a maintainer review

### PR checklist

- [ ] Tests pass: `make test`
- [ ] Linting passes: `make lint`
- [ ] Go build passes: `cd go && go build ./...`
- [ ] New check has documentation in `docs/checks/`
- [ ] Conventional commit messages
- [ ] No secrets or credentials in code

---

## Architecture Decision Records

Major design decisions are documented in `docs/adr/`. If your change involves an architectural decision, write an ADR:

- [ADR-001: Go+Python Hybrid Architecture](docs/adr/ADR-001-go-python-hybrid.md)
- [ADR-002: Newline-delimited JSON IPC](docs/adr/ADR-002-ndjson-ipc.md)
- [ADR-007: Open-source license + single-repo posture](docs/adr/ADR-007-open-source.md)

---

## Licensing of contributions

Fendix is MIT-licensed (see [`LICENSE`](LICENSE) and [ADR-007](docs/adr/ADR-007-open-source.md) for the strategic rationale).

**By submitting a pull request, you agree that your contribution is licensed under the same MIT terms as the rest of the tree.** No CLA, no copyright assignment, no separate paperwork. The Developer Certificate of Origin is satisfied by the act of submitting via your authenticated GitHub account.

If you're unsure whether code you're submitting is yours to contribute (e.g. employer ownership of work-time output, copy from another project), please flag it in the PR description so we can resolve it before merge.

### Out-of-tree plugins

Plugins distributed outside this repo via the plugin system (see `docs/plugins.md`) are **not** required to be MIT-licensed. Plugin authors choose their own license; the Fendix engine loads any plugin that implements the NDJSON contract. Plugins shipped *inside* this repo (under `examples/plugins/`) are MIT to match the rest of the tree.

---

## Questions?

Open an issue for feature requests, bug reports, or questions about contributing. We're happy to help newcomers get started.
