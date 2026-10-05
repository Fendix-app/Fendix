// Subcommand: `fendix engine` — inspect and refresh the Python whitebox
// engine that backs the AST taint analyzer (injection / SSTI / unsafe-deserialize
// / path-traversal detectors). Resolution mirrors engine.EnsureEngine:
//
//  1. --dir flag (explicit override)
//  2. FENDIX_ENGINE env var
//  3. FENDIX_ENGINE pinned in ~/.fendix/config (written by `engine sync`)
//  4. optional embedded payload extracted to ~/.fendix/engine (legacy or
//     custom builds only; official standalone releases do not carry one)
//  5. ./python relative to CWD (dev mode)
//
// Two operations:
//   - `fendix engine info` — show which engine path resolves and from where,
//     plus the Version stamp on disk. Useful for "why is this scan missing
//     findings" support questions.
//   - `fendix engine sync` — resolve the engine (explicit --dir / FENDIX_ENGINE,
//     else an optional embedded payload) and pin its location into ~/.fendix/config so
//     future invocations resolve automatically. Run once per environment; also
//     recovers from a hand-edited / partially-deleted ~/.fendix/engine.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Fendix-app/Fendix/go/internal/embedded"
	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/spf13/cobra"
)

func newEngineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine",
		Short: "Inspect or refresh the Python whitebox engine",
		Long: `Manage the Python engine that backs the AST analyzer (taint chains for
SQL injection / SSTI / pickle / yaml.load / path traversal). Official standalone
release binaries do not bundle this engine; point at a python/ source tree with
--dir or FENDIX_ENGINE. Docker images provide the tree separately.`,
	}
	cmd.AddCommand(newEngineInfoCmd())
	cmd.AddCommand(newEngineSyncCmd())
	return cmd
}

func newEngineInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show where the Python engine is loaded from",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Binary Version: %s\n", Version)
			if env := os.Getenv("FENDIX_ENGINE"); env != "" {
				fmt.Fprintf(out, "FENDIX_ENGINE:  %s\n", env)
			} else {
				fmt.Fprintln(out, "FENDIX_ENGINE:  (unset)")
			}
			if pinned := engine.PinnedEngineDir(); pinned != "" {
				fmt.Fprintf(out, "Pinned (config): %s\n", pinned)
			} else {
				fmt.Fprintln(out, "Pinned (config): (none — run 'fendix engine sync' to pin)")
			}
			fmt.Fprintf(out, "Embedded:       %v\n", embedded.HasEngine())

			path, err := engine.EnsureEngine("", Version)
			if err != nil {
				fmt.Fprintf(out, "Resolved:       (none — %s)\n", err)
				return nil
			}
			fmt.Fprintf(out, "Resolved:       %s\n", path)
			stampPath := filepath.Join(path, engine.VersionFile)
			if data, err := os.ReadFile(stampPath); err == nil {
				fmt.Fprintf(out, "Version stamp:  %s\n", string(data))
			} else {
				fmt.Fprintln(out, "Version stamp:  (not present)")
			}
			return nil
		},
	}
}

func newEngineSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pin the Python taint engine location for future invocations",
		Long: `Resolve the Python taint engine and pin its location for future scans.

Run this once per environment to pin the Python taint engine location.
After sync, FENDIX_ENGINE is written to ~/.fendix/config so future
invocations resolve automatically.

Resolution for the pin:
  1. --dir <path> (explicit), else the FENDIX_ENGINE env var if set, else
  2. an optional embedded engine (legacy/custom builds), re-extracted to
     ~/.fendix/engine.

Use this after manually editing files in ~/.fendix/engine to reset to a
known-good state, when troubleshooting why scans return fewer findings than
expected, or in CI before the scan step so a missing engine fails loudly
at sync time rather than silently degrading the SAST scan.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dirFlag, _ := cmd.Flags().GetString("dir")

			// Resolution order for what to pin:
			//   1. explicit --dir
			//   2. FENDIX_ENGINE env var pointing at a source tree
			//   3. the embedded payload (re-extracted to ~/.fendix/engine)
			var resolved string

			switch {
			case dirFlag != "" || os.Getenv("FENDIX_ENGINE") != "":
				// Validate the explicit source tree contains engine.py before
				// pinning it — pinning a bad path would just move the silent
				// no-op into "scans mysteriously fail later".
				dir, err := engine.EnsureEngine(dirFlag, Version)
				if err != nil {
					return fmt.Errorf("cannot pin engine: %w", err)
				}
				abs, err := filepath.Abs(dir)
				if err != nil {
					abs = dir
				}
				resolved = abs
				fmt.Fprintf(out, "Using engine source tree: %s\n", resolved)

			case embedded.HasEngine():
				dest, err := embedded.EngineDir()
				if err != nil {
					return fmt.Errorf("resolving engine destination: %w", err)
				}
				// Remove the existing tree so we don't leave orphan files
				// from a previous engine Version that this binary doesn't
				// know about. Safe — embedded.ExtractEngine repopulates.
				if err := os.RemoveAll(dest); err != nil {
					return fmt.Errorf("clearing %s: %w", dest, err)
				}
				count, err := embedded.ExtractEngine(dest)
				if err != nil {
					return fmt.Errorf("extracting engine: %w", err)
				}
				// Re-stamp so future binary-Version checks see the fresh extraction.
				if err := os.WriteFile(filepath.Join(dest, engine.VersionFile), []byte(Version), 0644); err != nil {
					return fmt.Errorf("writing Version stamp: %w", err)
				}
				abs, err := filepath.Abs(dest)
				if err != nil {
					abs = dest
				}
				resolved = abs
				fmt.Fprintf(out, "Re-extracted %d files to %s (stamped %s)\n", count, resolved, Version)

			default:
				return fmt.Errorf("this binary has no embedded engine — pass --dir <path> or set FENDIX_ENGINE to point at a python/ source tree, then re-run 'fendix engine sync'")
			}

			// Pin it: persist FENDIX_ENGINE into ~/.fendix/config so future
			// invocations resolve automatically without re-exporting the env
			// var in every shell / CI step.
			if err := engine.WriteConfigEngineDir(resolved); err != nil {
				return fmt.Errorf("pinning engine location: %w", err)
			}
			fmt.Fprintf(out, "Pinned FENDIX_ENGINE=%s in %s\n", resolved, engine.ConfigPath())
			return nil
		},
	}
	cmd.Flags().String("dir", "", "Explicit python/ engine source tree to pin (preferred for standalone releases)")
	return cmd
}
