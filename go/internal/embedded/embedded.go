// Package embedded preserves the optional legacy/custom-build path for a
// Python engine payload compiled into the Go binary. Official standalone
// builds intentionally embed only engine/.gitkeep: Makefile's embed-engine
// target resets the directory instead of copying python/. Docker images ship
// the Python source tree separately and point FENDIX_ENGINE at it.
//
// When a custom binary does contain a payload, ExtractEngine writes it to
// ~/.fendix/engine/ on first use.
package embedded

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// EngineFS contains an optional Python engine payload. Official builds contain
// only the placeholder required by go:embed.
//
//go:embed all:engine
var EngineFS embed.FS

// HasEngine reports whether the embedded filesystem contains real engine files
// (more than just the .gitkeep placeholder).
func HasEngine() bool {
	entries, err := fs.ReadDir(EngineFS, "engine")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != ".gitkeep" {
			return true
		}
	}
	return false
}

// ExtractEngine writes all embedded Python engine files to destDir.
// It creates destDir if it does not exist. Existing files are overwritten.
// Returns the number of files written.
func ExtractEngine(destDir string) (int, error) {
	if !HasEngine() {
		return 0, fmt.Errorf("no embedded engine files (binary built without embed-engine step)")
	}

	count := 0
	err := fs.WalkDir(EngineFS, "engine", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Strip the leading "engine/" prefix to get relative path
		relPath, err := filepath.Rel("engine", path)
		if err != nil {
			return fmt.Errorf("computing relative path for %s: %w", path, err)
		}

		// Skip the root and the placeholder
		if relPath == "." || d.Name() == ".gitkeep" {
			return nil
		}

		destPath := filepath.Join(destDir, relPath)

		if d.IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("creating directory %s: %w", destPath, err)
			}
			return nil
		}

		data, err := EngineFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading embedded file %s: %w", path, err)
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("creating parent directory for %s: %w", destPath, err)
		}

		if err := os.WriteFile(destPath, data, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", destPath, err)
		}

		count++
		return nil
	})

	if err != nil {
		return count, fmt.Errorf("extracting engine: %w", err)
	}

	return count, nil
}

// EngineDir returns the default extraction path: ~/.fendix/engine/
func EngineDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".fendix", "engine"), nil
}
