package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/Fendix-app/Fendix/go/internal/cli"
	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/spf13/cobra"
)

// runImport executes the standalone import pipeline. Package var for the
// same reason as runScan: a test seam.
var runImport = func(ctx context.Context, cfg *models.ScanConfig, version string) int {
	return engine.NewOrchestrator(cfg, version).RunImport(ctx)
}

// newImportCmd is the standalone `fendix import`: ingest SARIF 2.1.0 reports
// produced by OTHER scanners and run them through the full fendix flow —
// normalization, fingerprinting, deterministic confidence scoring, dedup,
// .fendix-ignore / --baseline, confidence-gated --fail-on, and every report
// format. The exit contract matches `scan`: 0 clean, 1 when a finding
// BLOCKs, 2 on error.
func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file.sarif> [more.sarif ...]",
		Short: "Import SARIF reports from other scanners and gate/report on them",
		Long: "Normalize SARIF 2.1.0 findings from other scanners (CodeQL, semgrep, trivy, …) " +
			"into fendix findings and run the standard pipeline: deterministic confidence " +
			"scoring, dedup, ignore/baseline filtering, confidence-gated --fail-on, and the " +
			"full reporter set. Pass '-' to read stdin. To merge imports into a live fendix " +
			"scan instead, use `fendix scan --import <file.sarif>`.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			outputFlag, _ := flags.GetString("output")
			formatFlag, _ := flags.GetString("format")
			failOnFlag, _ := flags.GetString("fail-on")
			failOnFlag, err := models.ParseFailOn(failOnFlag)
			if err != nil {
				return err
			}
			baselineFlag, _ := flags.GetString("baseline")
			saveBaselineFlag, _ := flags.GetString("save-baseline")
			ignoreFlag, _ := flags.GetString("ignore")
			targetFlag, _ := flags.GetString("target")
			langFlag, _ := flags.GetString("lang")
			deescalateTestsFlag, _ := flags.GetBool("deescalate-tests")
			enforceConfidenceFlag, _ := flags.GetBool("enforce-confidence")

			cfg := &models.ScanConfig{
				// URL doubles as the report's target label; an import has no
				// scanned target of its own.
				URL:               targetFlag,
				ImportPaths:       args,
				OutputPath:        outputFlag,
				Format:            formatFlag,
				FailOn:            failOnFlag,
				BaselinePath:      baselineFlag,
				SaveBaselinePath:  saveBaselineFlag,
				IgnorePath:        ignoreFlag,
				Lang:              resolveLang(langFlag, cmd.ErrOrStderr()),
				DeescalateTests:   deescalateTestsFlag,
				EnforceConfidence: enforceConfidenceFlag,
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			exitCode := runImport(ctx, cfg, Version)
			if exitCode != 0 {
				return cli.ExitWithCode(exitCode, "")
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringP("output", "o", "", "Output file path (default: stdout)")
	flags.StringP("format", "f", "json", "Output format: json, html, sarif, pdf")
	flags.String("fail-on", "", "Exit 1 if a finding at this severity reaches BLOCK: CRITICAL, HIGH, MEDIUM, LOW (confidence gating applies — see --enforce-confidence)")
	flags.String("baseline", "", "Path to previous findings JSON for diff mode")
	flags.String("save-baseline", "", "Save current findings to this path")
	flags.String("ignore", "", "Path to .fendix-ignore file")
	flags.String("target", "", "Optional label stamped into report metadata (an import has no scanned target of its own)")
	flags.String("lang", "en", "HTML report language: en (default), ar (Arabic, RTL). Other formats stay English.")
	flags.Bool("deescalate-tests", true, "Report findings in test/fixture code as INFO instead of WARN (evidence is preserved, never suppressed). Pass --deescalate-tests=false to treat test-code findings like production ones.")
	flags.Bool("enforce-confidence", true, "Only BLOCK a finding at or above --fail-on when its confidence band and evidence support it: LOW warns; MEDIUM needs an independent signal; HIGH needs an independent or self-evident signal. Pass --enforce-confidence=false to restore the legacy severity-only gate — findings that block only because of that relaxation are marked policy_override in the report.")

	// Reject an unknown format early with the same wording style as scan.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		f, _ := cmd.Flags().GetString("format")
		switch f {
		case "json", "html", "sarif", "pdf":
			return nil
		default:
			return fmt.Errorf("unsupported --format %q — use json, html, sarif, or pdf", f)
		}
	}

	return cmd
}
