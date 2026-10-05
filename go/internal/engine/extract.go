package engine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/embedded"
)

// VersionFile is written to the engine directory after extraction.
// On upgrade, if the binary version differs, re-extract.
const VersionFile = ".fendix-version"

// EngineNotFoundError is returned by EnsureEngine when no usable Python taint
// engine could be resolved from any source. It carries the list of locations
// that were searched so the message is actionable (and so callers can decide
// whether a missing engine is fatal — it is when --code/--python-engine asked
// for SAST, harmless otherwise). Its Error() text is a hard contract consumed
// by tests and the CLI's exit message; do not reword without updating both.
type EngineNotFoundError struct {
	Searched []string
}

func (e *EngineNotFoundError) Error() string {
	searched := "(none)"
	if len(e.Searched) > 0 {
		searched = strings.Join(e.Searched, ", ")
	}
	return fmt.Sprintf(
		"Python taint engine not found. Searched: [%s].\n"+
			"Fix: set FENDIX_ENGINE=/path/to/python or run 'fendix engine sync'.",
		searched,
	)
}

// EnsureEngine returns a path to a usable Python engine directory.
// Resolution order:
//  1. If engineDir is set (dev mode / explicit config), use it directly.
//  2. If FENDIX_ENGINE env var is set, use that (matches the --help and
//     package doc promise; lets CI / E2E tests point at the repo's
//     python/ tree without changing CWD).
//     2b. If FENDIX_ENGINE is pinned in ~/.fendix/config (by `fendix engine
//     sync`), use that — the once-per-environment pin.
//  3. If embedded FS has engine files, extract to ~/.fendix/engine/ and return that.
//  4. Fall back to "python" relative to CWD (source tree development).
//
// On total failure it returns *EngineNotFoundError, whose message names every
// location probed and the fix-it steps. Callers that requested SAST treat that
// as fatal (see orchestrator.Run); non-SAST callers never invoke EnsureEngine.
//
// The version parameter is the Go binary version (e.g. "1.0.0" or "dev").
// If the extracted engine has a different version stamp, it is re-extracted.
func EnsureEngine(engineDir, version string) (string, error) {
	// searched accumulates every location we probe for engine.py so a
	// final "not found" reports exactly where it looked (see
	// EngineNotFoundError). The explicit-dir and FENDIX_ENGINE branches
	// below return their own specific errors and never reach the
	// fall-through, so those paths are reported there instead.
	var searched []string

	// 1. Explicit engine directory — use directly
	if engineDir != "" {
		enginePy := filepath.Join(engineDir, "engine.py")
		if _, err := os.Stat(enginePy); err == nil {
			slog.Debug("using explicit engine directory", "dir", engineDir)
			return engineDir, nil
		}
		// An explicit --dir that lacks engine.py is "not found", reported via
		// the canonical EngineNotFoundError so the message/exit contract is
		// uniform — the bad path lands in Searched, keeping it actionable.
		return "", &EngineNotFoundError{Searched: []string{enginePy + " (--dir)"}}
	}

	// 2. FENDIX_ENGINE env override — documented in --python-engine's
	// flag description. Lets CI / tests point at an absolute path
	// without depending on the binary's CWD.
	if envDir := os.Getenv("FENDIX_ENGINE"); envDir != "" {
		enginePy := filepath.Join(envDir, "engine.py")
		if _, err := os.Stat(enginePy); err == nil {
			slog.Debug("using FENDIX_ENGINE directory", "dir", envDir)
			return envDir, nil
		}
		// FENDIX_ENGINE pointed somewhere without engine.py. Still "engine not
		// found"; surface the canonical error so the CLI prints the same
		// fix-it text (set FENDIX_ENGINE / run 'fendix engine sync') and the
		// bad path is named in Searched.
		return "", &EngineNotFoundError{Searched: []string{enginePy + " (FENDIX_ENGINE)"}}
	}

	// 2b. Persisted FENDIX_ENGINE from ~/.fendix/config (written by
	// `fendix engine sync`). This is the "pin it once per environment"
	// path: after sync, future invocations resolve here without the user
	// re-exporting FENDIX_ENGINE in every shell / CI step. Lower precedence
	// than a live env var (an explicit export always wins) and than an
	// explicit --dir, but higher than embedded extraction so an operator who
	// deliberately pinned a source tree gets it over a stale embedded copy.
	if cfgDir := configEngineDir(); cfgDir != "" {
		enginePy := filepath.Join(cfgDir, "engine.py")
		if _, err := os.Stat(enginePy); err == nil {
			slog.Debug("using FENDIX_ENGINE from ~/.fendix/config", "dir", cfgDir)
			return cfgDir, nil
		}
		// A pinned-but-now-missing path is recorded in the searched list so a
		// later "not found" tells the user their pin went stale (e.g. the
		// source tree moved) — but we keep probing the remaining sources.
		searched = append(searched, enginePy+" (~/.fendix/config)")
	}

	// 3. Try embedded extraction
	if embedded.HasEngine() {
		destDir, err := embedded.EngineDir()
		if err != nil {
			return "", fmt.Errorf("determining engine directory: %w", err)
		}

		if needsExtraction(destDir, version) {
			slog.Info("extracting embedded python engine", "dest", destDir)
			count, err := embedded.ExtractEngine(destDir)
			if err != nil {
				return "", fmt.Errorf("extracting engine: %w", err)
			}
			slog.Info("python engine extracted", "files", count, "dest", destDir)

			// Write version stamp
			if err := writeVersionStamp(destDir, version); err != nil {
				slog.Warn("failed to write version stamp", "error", err)
			}
		} else {
			slog.Debug("embedded engine already extracted", "dir", destDir)
		}

		return destDir, nil
	}

	// 4. Fall back to local "python" directory (development mode)
	localDir := "python"
	localEnginePy := filepath.Join(localDir, "engine.py")
	if _, err := os.Stat(localEnginePy); err == nil {
		slog.Debug("using local python engine directory", "dir", localDir)
		return localDir, nil
	}
	// Record the resolved absolute path we probed so the error is concrete
	// regardless of the caller's CWD.
	if abs, err := filepath.Abs(localEnginePy); err == nil {
		searched = append(searched, abs)
	} else {
		searched = append(searched, localEnginePy)
	}

	return "", &EngineNotFoundError{Searched: searched}
}

// ConfigPath returns the path to the persistent fendix config file
// (~/.fendix/config). `fendix engine sync` writes the resolved engine
// location here as FENDIX_ENGINE=<path>; EnsureEngine reads it back so a
// one-time sync pins the engine for every future invocation. Returns "" if
// the home directory can't be determined (config is then simply skipped —
// never fatal).
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".fendix", "config")
}

// PinnedEngineDir returns the FENDIX_ENGINE value pinned in ~/.fendix/config
// (by `fendix engine sync`), or "" if nothing is pinned. Exported for the
// `fendix engine info` command so operators can see the pin without scanning.
func PinnedEngineDir() string {
	return configEngineDir()
}

// configEngineDir reads the persisted FENDIX_ENGINE value from
// ~/.fendix/config, or "" if the file is absent / unreadable / has no such
// key. The format is a minimal KEY=VALUE file (one per line; '#' comments and
// blank lines ignored) — deliberately not YAML, so reading it pulls in no
// parser and can never fail-closed on a syntax quirk. A malformed file just
// yields no value and resolution falls through to the next source.
func configEngineDir() string {
	path := ConfigPath()
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "FENDIX_ENGINE" {
			// Strip optional surrounding quotes for robustness against a
			// hand-edited file (FENDIX_ENGINE="/path with spaces").
			return strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	return ""
}

// WriteConfigEngineDir persists engineDir as FENDIX_ENGINE in
// ~/.fendix/config so future invocations resolve it automatically (the
// `fendix engine sync` pin). It rewrites the file preserving any unrelated
// KEY=VALUE lines and replacing/appending the FENDIX_ENGINE line. Creates the
// ~/.fendix directory if needed.
func WriteConfigEngineDir(engineDir string) error {
	path := ConfigPath()
	if path == "" {
		return fmt.Errorf("cannot determine home directory for ~/.fendix/config")
	}
	// 0o700: ~/.fendix is owner-only. The config can pin the engine source
	// tree path; this is a security product, so we keep the whole dir off
	// other local users rather than just the file.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	// Preserve existing non-FENDIX_ENGINE lines; replace the FENDIX_ENGINE
	// line in place if present, otherwise append it.
	var out []string
	replaced := false
	newLine := fmt.Sprintf("FENDIX_ENGINE=%s", engineDir)
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if key, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(key) == "FENDIX_ENGINE" {
				out = append(out, newLine)
				replaced = true
				continue
			}
			out = append(out, line)
		}
		// Drop a single trailing empty element from the split so we don't
		// accumulate blank lines on repeated writes.
		if n := len(out); n > 0 && out[n-1] == "" {
			out = out[:n-1]
		}
	}
	if !replaced {
		out = append(out, newLine)
	}

	content := strings.Join(out, "\n") + "\n"
	// 0o600: owner read/write only — never world-readable (security review).
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// needsExtraction returns true if the engine needs to be extracted or re-extracted.
func needsExtraction(destDir, version string) bool {
	// Check if engine.py exists
	if _, err := os.Stat(filepath.Join(destDir, "engine.py")); os.IsNotExist(err) {
		return true
	}

	// Check version stamp
	stampPath := filepath.Join(destDir, VersionFile)
	stamp, err := os.ReadFile(stampPath)
	if err != nil {
		return true // No stamp — re-extract
	}

	// Dev builds always re-extract (version changes frequently during development)
	if version == "dev" || version == "" {
		return false // Don't re-extract in dev mode — wastes time
	}

	return string(stamp) != version
}

// writeVersionStamp writes the version to the engine directory.
func writeVersionStamp(destDir, version string) error {
	stampPath := filepath.Join(destDir, VersionFile)
	return os.WriteFile(stampPath, []byte(version), 0o644)
}
