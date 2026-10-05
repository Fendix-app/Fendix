package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/metrics"
	"github.com/spf13/cobra"
)

// newMetricsCmd is the `fendix metrics` command group (v0.20). It reads the
// opt-in local event log (FENDIX_METRICS) and never makes a network call.
func newMetricsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Inspect local product metrics (opt-in via FENDIX_METRICS)",
		Long: `Show, export, or clear the local metrics event log written when
FENDIX_METRICS is set. All data stays on disk (` + metrics.ResolvePath() + `);
nothing is ever sent anywhere.`,
	}
	cmd.AddCommand(newMetricsShowCmd(), newMetricsExportCmd(), newMetricsClearCmd())
	return cmd
}

func newMetricsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print a summary of the last 30 scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			events, err := metrics.LoadEvents(metrics.ResolvePath())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(events) == 0 {
				fmt.Fprintf(out, "No metrics recorded yet. Enable with FENDIX_METRICS=true and run a scan.\n")
				return nil
			}
			s := metrics.Summarize(events, 30)
			arrow := map[string]string{"improving": "↓ improving", "worsening": "↑ worsening", "flat": "→ flat"}[s.DurationTrend]
			fmt.Fprintf(out, "Fendix metrics — last %d scans\n", s.Count)
			fmt.Fprintln(out, "─────────────────────────────")
			fmt.Fprintf(out, "Total scans:        %d\n", s.Count)
			fmt.Fprintf(out, "Avg duration:       %.1fs\n", s.AvgDurationMs/1000)
			fmt.Fprintf(out, "Avg findings:       %.1f\n", s.AvgFindings)
			fmt.Fprintf(out, "Avg memory:         %.0fMB\n", s.AvgMemoryMB)
			fmt.Fprintf(out, "Last run:           %s\n", s.LastRun.Format("2006-01-02 15:04 MST"))
			fmt.Fprintf(out, "Trend (duration):   %s\n", arrow)

			// CLI success rate (v0.25): spans ALL recorded invocations, not
			// just scans. Only shown once per-invocation events exist, so an
			// older scan-only log doesn't print a misleading 0%.
			if cs := metrics.SummarizeCommands(events, 0); cs.Total > 0 {
				meets := "✓"
				if cs.SuccessRate < 0.95 {
					meets = "✗ below target"
				}
				fmt.Fprintln(out, "─────────────────────────────")
				fmt.Fprintf(out, "CLI success rate:   %.1f%% (%d/%d, target ≥95%% %s)\n",
					cs.SuccessRate*100, cs.Success, cs.Total, meets)
				if len(cs.ByErrorClass) > 0 {
					for _, k := range sortedKeys(cs.ByErrorClass) {
						fmt.Fprintf(out, "  failures (%s): %d\n", k, cs.ByErrorClass[k])
					}
				}
			}
			return nil
		},
	}
}

// sortedKeys returns a map's keys in stable order so the failure-class
// breakdown prints deterministically (and is snapshot-testable).
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func newMetricsExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Dump all recorded events",
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, _ := cmd.Flags().GetBool("json")
			events, err := metrics.LoadEvents(metrics.ResolvePath())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(events)
			}
			// Default: re-emit the raw NDJSON.
			enc := json.NewEncoder(out)
			for _, e := range events {
				if err := enc.Encode(e); err != nil {
					return fmt.Errorf("encoding event: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "Emit a single indented JSON array instead of NDJSON")
	return cmd
}

func newMetricsClearCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete the local metrics event log",
		RunE: func(cmd *cobra.Command, args []string) error {
			yes, _ := cmd.Flags().GetBool("yes")
			out := cmd.OutOrStdout()
			if _, err := os.Stat(metrics.ResolvePath()); os.IsNotExist(err) {
				fmt.Fprintln(out, "Nothing to clear — no metrics log exists.")
				return nil
			}
			if !yes {
				fmt.Fprintf(out, "Delete %s? [y/N] ", metrics.ResolvePath())
				reader := bufio.NewReader(cmd.InOrStdin())
				line, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(line)) != "y" {
					fmt.Fprintln(out, "Aborted.")
					return nil
				}
			}
			if err := os.Remove(metrics.ResolvePath()); err != nil {
				return fmt.Errorf("removing metrics log: %w", err)
			}
			fmt.Fprintf(out, "Removed %s\n", metrics.ResolvePath())
			return nil
		},
	}
	cmd.Flags().Bool("yes", false, "Skip the confirmation prompt")
	return cmd
}
