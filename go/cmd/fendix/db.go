package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/offline"
	"github.com/spf13/cobra"
)

const offlineDBPathHelp = "~/.fendix/offline-db.json"

// newDBCmd wires the Sprint-09 offline-mode CLI surface. Three
// subcommands matching the brief:
//
//	fendix db list                     — show the local snapshot's metadata
//	fendix db update --source <file>   — ingest an OSV.dev export into the snapshot
//	fendix db verify                   — recompute the snapshot's SHA-256
//
// The runtime integration (`--offline` flag on `scan` that swaps
// every dep-CVE check from live HTTP to the snapshot) is wired
// separately in main.go's scan command and lives in the per-ecosystem
// scanners as TODO comments — Sprint 09 ships the format + tooling +
// CLI surface so customer ops can produce a snapshot in a connected
// environment and copy it to the air-gapped one.
func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the offline CVE-database snapshot (Sprint 09)",
		Long: `Manage Fendix's air-gapped CVE database snapshot — for customers whose
CI runners can't reach osv.dev / golang.org/x/vuln.

Typical workflow:

  # On a connected machine
  fendix db update --source osv-export.json --output offline-db.json

  # Copy offline-db.json to the air-gapped runner

  # On the air-gapped runner
  fendix db list --path offline-db.json
  fendix db verify --path offline-db.json
  fendix scan --code . --offline --offline-db offline-db.json

The snapshot format is documented in
internal/offline/offline.go's package doc.`,
	}
	cmd.AddCommand(newDBListCmd())
	cmd.AddCommand(newDBUpdateCmd())
	cmd.AddCommand(newDBVerifyCmd())
	return cmd
}

func newDBListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print metadata about the local offline snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("path")
			if path == "" {
				path = offline.DefaultDBPath()
			}
			snap, err := offline.Read(path)
			if err != nil {
				if errors.Is(err, offline.ErrSnapshotMissing) {
					return fmt.Errorf("offline snapshot not found at %s. Run: fendix db update --source <osv-export.json> --output %s", path, path)
				}
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), snap.Summary())
			return nil
		},
	}
	cmd.Flags().String("path", "", "Path to the snapshot file (default: "+offlineDBPathHelp+")")
	return cmd
}

func newDBUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Ingest an OSV advisory export into a fendix offline snapshot",
		Long: `Reads a JSON file containing a list of OSV-shaped advisories and writes
a fendix offline snapshot. The input can be either a top-level array of
OSV objects or a wrapper object with an "advisories" field.

The OSV.dev nightly mirror at https://osv-vulnerabilities.storage.googleapis.com/
publishes per-ecosystem zips; extract them and concatenate to feed
this command.`,
		Example: `  fendix db update --source osv-export.json
  fendix db update --source osv-export.json --output ./offline-db.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			source, _ := cmd.Flags().GetString("source")
			output, _ := cmd.Flags().GetString("output")
			if source == "" {
				return errors.New("--source is required (path to an OSV-shaped JSON export)")
			}
			if output == "" {
				output = offline.DefaultDBPath()
			}
			return runDBUpdate(cmd.OutOrStdout(), source, output)
		},
	}
	cmd.Flags().String("source", "", "Path to an OSV-shaped JSON export to ingest")
	cmd.Flags().String("output", "", "Where to write the snapshot (default: "+offlineDBPathHelp+")")
	return cmd
}

func newDBVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Print the SHA-256 of the local snapshot for integrity verification",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("path")
			if path == "" {
				path = offline.DefaultDBPath()
			}
			hash, snap, err := offline.Verify(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "sha256 %s  %s\n", hash, path)
			fmt.Fprintln(cmd.OutOrStdout(), snap.Summary())
			return nil
		},
	}
	cmd.Flags().String("path", "", "Path to the snapshot file (default: "+offlineDBPathHelp+")")
	return cmd
}

// runDBUpdate reads source, parses either shape (array or wrapper),
// and writes a snapshot to outputPath.
func runDBUpdate(w io.Writer, sourcePath, outputPath string) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source %s: %w", sourcePath, err)
	}
	advisories, err := parseOSVExport(data)
	if err != nil {
		return fmt.Errorf("parse source %s: %w", sourcePath, err)
	}
	// Record only the source filename in the snapshot — the operator's
	// full local path can include usernames, build paths, or scratch
	// directories that shouldn't ship to air-gapped recipients.
	snap := offline.FromOSVExport(advisories, []string{filepath.Base(sourcePath)})
	snap.GeneratedAt = time.Now().UTC()
	if err := offline.Write(outputPath, snap); err != nil {
		return err
	}
	fmt.Fprintf(w, "✓ Wrote %d advisories to %s\n", len(advisories), outputPath)
	return nil
}

func parseOSVExport(data []byte) ([]offline.Advisory, error) {
	// Try wrapper shape first: {"advisories": [...]}
	var wrapper struct {
		Advisories []offline.Advisory `json:"advisories"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Advisories != nil {
		return wrapper.Advisories, nil
	}
	// Bare top-level array.
	var bare []offline.Advisory
	if err := json.Unmarshal(data, &bare); err != nil {
		return nil, err
	}
	return bare, nil
}
