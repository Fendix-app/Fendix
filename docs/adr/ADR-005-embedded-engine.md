# ADR-005: Embedded Python Engine Distribution

## Status

Superseded by TASK-118.

## Superseding implementation

Official source and release builds intentionally embed only the `.gitkeep`
placeholder required by `//go:embed`. `make embed-engine` resets the directory;
it does not copy `python/`. The compatibility extraction code remains for
legacy/custom binaries that contain a payload.

Source builds can resolve a local `./python` tree. Official Docker images copy
the tree to `/opt/fendix/python/` and set `FENDIX_ENGINE`. A standalone release
requires an explicit/local tree for the Python checks.

The decision below is historical and must not be used to infer current release
contents.

## Context

Users need to install and run Fendix with minimal friction. The Go binary is a single file, but the Python engine requires additional files (engine.py, analyzers/, rules/). We need a distribution strategy that works for both:

1. **End users** who want a single binary with everything included
2. **Developers** who want to modify and test the Python engine locally

## Decision

Use Go's `//go:embed` to bundle Python engine files into the binary at build time:

1. **Build time:** `make embed-engine` copies `python/` files into `go/internal/embedded/engine/`
2. **Compilation:** `//go:embed all:engine` bundles the directory into the binary
3. **First run:** `EnsureEngine()` extracts files to `~/.fendix/engine/` with a version stamp
4. **Upgrade:** Version stamp triggers re-extraction when binary version changes
5. **Dev mode:** Falls back to local `python/` directory if present

**3-tier fallback order:**
1. Explicit `--engine-dir` flag (testing/debugging)
2. Embedded extraction to `~/.fendix/engine/`
3. Local `python/` directory (development)

## Consequences

**Positive:**
- Single binary distribution for end users
- No manual Python file management
- Automatic re-extraction on upgrade
- Development workflow unaffected (local fallback)

**Negative:**
- Binary size increases by ~200KB (Python source files)
- First run has ~100ms extraction overhead
- `.gitkeep` placeholder needed for dev builds without embed step

**Mitigations:**
- Version stamp prevents unnecessary re-extraction
- Dev builds skip re-extraction entirely ("dev" version)
- Build step is integrated into Makefile and CI
