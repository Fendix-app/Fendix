# ADR-001: Go + Python Hybrid Architecture

## Status

Accepted as the hybrid architecture; amended by the current native-scanner and
distribution implementation described below.

The original "single binary with embedded Python" consequence was superseded
when TASK-118 removed the Python payload from official standalone builds. See
[ADR-005](ADR-005-embedded-engine.md).

## Current implementation addendum

Go now owns DAST, secrets, textscan, Semgrep orchestration and native SCA.
Python remains the subprocess implementation for AST/spec/dependency checks.
`--code` auto-enables that subprocess unless `--python-engine=false` is
explicit, but official standalone binaries do not contain its source tree.
Source checkouts resolve `./python`; official containers provide
`/opt/fendix/python/` through `FENDIX_ENGINE`.

## Context

Fendix needs two fundamentally different capabilities:

1. **Black-box HTTP scanning** — sending real HTTP requests, parsing responses, detecting misconfigurations. This requires high concurrency (many endpoints in parallel), low latency, and a single distributable binary.

2. **White-box static analysis** — parsing source code ASTs, running Semgrep rules, detecting hardcoded secrets. This requires access to the best security tooling ecosystem, which exists in Python (Semgrep, Bandit, detect-secrets).

No single language excels at both. Go is ideal for networked CLI tools but lacks a mature security analysis ecosystem. Python has the best security tools but is slow for concurrent HTTP work and harder to distribute as a single binary.

## Decision

Build Fendix as a hybrid system:

- **Go** for the CLI interface, HTTP scanner, orchestrator, and report renderer. Go compiles to a single binary, has excellent concurrency primitives (goroutines), and provides fast HTTP client performance.

- **Python** for the static analysis engine. Python has Semgrep, Bandit, detect-secrets, and a mature AST library. The Python engine runs as a subprocess spawned by Go.

- **Communication** via newline-delimited JSON over stdin/stdout (see ADR-002).

The user interacts only with the Go binary. Python is an implementation detail.

## Consequences

**Positive:**
- Best tool for each job — Go for networking, Python for analysis
- A standalone Go CLI plus an optional external Python analysis tree
- Python engine is independently runnable for debugging
- Clean separation of concerns between engines
- Each engine can be tested independently

**Negative:**
- Two language ecosystems to maintain (Go modules + pip)
- Subprocess spawning adds ~1-2 seconds startup latency for Python engine
- Users need Python installed for white-box features (mitigated by graceful fallback)
- IPC contract must be maintained in sync across both languages

**Mitigations:**
- Python engine startup budget: < 2 seconds (measured and tested)
- Graceful degradation: if Python is not installed, skip white-box analysis with a clear message
- CI validates both Go and Python on every push
- IPC contract is documented in MEMORY.md and tested end-to-end
