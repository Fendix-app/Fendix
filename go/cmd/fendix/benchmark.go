package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/internal/benchmark/targets"
	"github.com/Fendix-app/Fendix/go/internal/cli"
	"github.com/spf13/cobra"
)

// newBenchmarkCmd is the `fendix benchmark` command group (v0.20 —
// Establish Baselines). INTERNAL tooling: it does not change scan
// behavior or output. It runs the accuracy + performance benchmark suite
// and gates releases on regression-vs-stored-baseline.
func newBenchmarkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run the internal accuracy + performance benchmark suite",
		Long: `Run Fendix against known-vulnerable corpora (OWASP Benchmark, DVWA,
Juice Shop) and score the results against ground truth, producing the
precision/recall/FP/FN + duration baseline every future release compares
against.

DAST targets (DVWA, Juice Shop) require Docker. OWASP Benchmark is Java and
is SKIPPED until Java support lands in v0.27.`,
	}
	cmd.AddCommand(newBenchmarkRunCmd(), newBenchmarkBaselineCmd(), newBenchmarkCompareCmd())
	return cmd
}

func selectTargets(name string) ([]targets.Target, error) {
	if name == "" || name == "all" {
		return targets.All(), nil
	}
	t, err := targets.ByName(name)
	if err != nil {
		return nil, err
	}
	return []targets.Target{t}, nil
}

// runSuite scans and scores each target. Targets that report ErrTargetSkipped
// from Scan() (e.g. OWASP — Java, needs deep taint; SKIPPED until v0.28+) are
// noted and omitted, not treated as failures. OWASP also returns
// ErrTargetSkipped from Run() as defence in depth, but Scan() short-circuits
// here first so Run() is never reached for it.
func runSuite(ctx context.Context, fendixBin string, ts []targets.Target, out io.Writer) ([]benchmark.BenchmarkResult, error) {
	var results []benchmark.BenchmarkResult
	for _, t := range ts {
		fmt.Fprintf(out, "→ %s: scanning...\n", t.Name())
		sr, err := t.Scan(ctx, fendixBin)
		if err != nil {
			if errors.Is(err, targets.ErrTargetSkipped) {
				fmt.Fprintf(out, "  SKIPPED: %v\n", err)
				continue
			}
			return nil, err
		}
		res, err := t.Run(ctx, sr)
		if err != nil {
			return nil, err
		}
		results = append(results, *res)
	}
	return results, nil
}

func printResults(out io.Writer, results []benchmark.BenchmarkResult, base *benchmark.Baseline) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Target\tPrecision\tRecall\tFPRate\tF1\tDuration\tvs Baseline")
	labelLimited := false
	for _, r := range results {
		vs := "BASELINE (first run)"
		if base != nil {
			if b, ok := base.Results[r.Target]; ok {
				vs = fmt.Sprintf("%+.1f%% recall", (r.Recall()-b.Recall())*100)
			}
		}
		// FPRate is only meaningful with a labeled negative corpus. DAST
		// targets have none (TrueNeg==0), so show n/a rather than a
		// degenerate "100%". Precision is likewise a lower bound when the
		// ground truth lists only confirmed positives.
		fpRate := "n/a"
		if r.TrueNeg > 0 {
			fpRate = fmt.Sprintf("%.1f%%", r.FPRate()*100)
		} else {
			labelLimited = true
		}
		fmt.Fprintf(tw, "%s\t%.1f%%\t%.1f%%\t%s\t%.3f\t%s\t%s\n",
			r.Target,
			r.Precision()*100, r.Recall()*100, fpRate, r.F1(),
			r.ScanDuration.Round(time.Millisecond), vs)
	}
	_ = tw.Flush()
	if labelLimited {
		fmt.Fprintln(out, "note: FPRate=n/a and precision is a lower bound for targets with no labeled negative corpus (DAST). Recall + duration are the reliable v0.20 signals.")
	}
}

// printRealWorldTriage dumps each real-world target's per-class FP breakdown +
// unlabeled-finding triage list after the scored results table, so labeling
// stays incremental and the precision number stays defensible.
func printRealWorldTriage(out io.Writer, ts []targets.Target) {
	for _, t := range ts {
		if rw, ok := t.(*targets.RealWorld); ok {
			if report := rw.TriageReport(); report != "" {
				fmt.Fprint(out, report)
			}
		}
	}
}

func writeResults(path string, results []benchmark.BenchmarkResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating results dir: %w", err)
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding results: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing results %s: %w", path, err)
	}
	return nil
}

func benchmarkContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(cmd.Context(), os.Interrupt)
}

func newBenchmarkRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the benchmark suite and print scored results",
		Example: `  fendix benchmark run                       # all targets
  fendix benchmark run --target juiceshop    # one target
  fendix benchmark run --output benchmarks/results/run.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			output, _ := cmd.Flags().GetString("output")
			ts, err := selectTargets(target)
			if err != nil {
				return err
			}
			bin, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving fendix binary: %w", err)
			}
			ctx, cancel := benchmarkContext(cmd)
			defer cancel()

			results, err := runSuite(ctx, bin, ts, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			base, _ := benchmark.Load(benchmark.DefaultBaselinePath) // best-effort for the vs column
			printResults(cmd.OutOrStdout(), results, base)
			printRealWorldTriage(cmd.OutOrStdout(), ts)
			if output != "" {
				if err := writeResults(output, results); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().String("target", "all", "Target to run: owasp, dvwa, juiceshop, or all")
	cmd.Flags().String("output", "", "Write scored results JSON to this path")
	return cmd
}

func newBenchmarkBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Run the suite and (with --save) store the result as the committed baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			save, _ := cmd.Flags().GetBool("save")
			target, _ := cmd.Flags().GetString("target")
			ts, err := selectTargets(target)
			if err != nil {
				return err
			}
			bin, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving fendix binary: %w", err)
			}
			ctx, cancel := benchmarkContext(cmd)
			defer cancel()

			results, err := runSuite(ctx, bin, ts, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			printResults(cmd.OutOrStdout(), results, nil)
			printRealWorldTriage(cmd.OutOrStdout(), ts)

			b := &benchmark.Baseline{
				Version:   Version,
				CreatedAt: time.Now().UTC(),
				Results:   make(map[string]benchmark.BenchmarkResult, len(results)),
			}
			for _, r := range results {
				b.Results[r.Target] = r
			}
			if !save {
				fmt.Fprintf(cmd.OutOrStdout(), "\nDry run — pass --save to write %s\n", benchmark.DefaultBaselinePath)
				return nil
			}
			if err := b.Save(benchmark.DefaultBaselinePath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n✓ Baseline saved to %s (%d targets)\n", benchmark.DefaultBaselinePath, len(b.Results))
			return nil
		},
	}
	cmd.Flags().Bool("save", false, "Persist this run as the committed baseline")
	cmd.Flags().String("target", "all", "Target to baseline: owasp, dvwa, juiceshop, or all")
	return cmd
}

func newBenchmarkCompareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Run the suite and fail if any metric regressed >10% vs the committed baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := benchmark.Load(benchmark.DefaultBaselinePath)
			if err != nil {
				return fmt.Errorf("no committed baseline (run `fendix benchmark baseline --save` first): %w", err)
			}
			bin, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving fendix binary: %w", err)
			}
			ctx, cancel := benchmarkContext(cmd)
			defer cancel()

			results, err := runSuite(ctx, bin, targets.All(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			printResults(cmd.OutOrStdout(), results, base)

			report := base.Compare(results)
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "\nRegression report (threshold ±10% in the worse direction):")
			for _, d := range report.Deltas {
				if d.Regression {
					fmt.Fprintf(out, "  REGRESSION  %s/%s: %.4f → %.4f (%+.1f%%)\n",
						d.Target, d.Metric, d.Baseline, d.Current, d.PctChange*100)
				}
			}
			for _, nt := range report.NewTargets {
				fmt.Fprintf(out, "  NEW TARGET  %s (no baseline entry — recorded, not gated)\n", nt)
			}
			if report.HasRegression() {
				return cli.ExitWithCode(1, "benchmark regression detected")
			}
			fmt.Fprintln(out, "  ✓ no regressions")
			return nil
		},
	}
	return cmd
}
