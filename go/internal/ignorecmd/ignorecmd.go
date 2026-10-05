// Package ignorecmd implements the `fendix ignore …` cobra
// subcommand tree introduced in TASK-135 / Phase 17d.
//
// Three subcommands:
//
//	fendix ignore list      — show all rules in .fendix-ignore + expiry status
//	fendix ignore validate  — parse the file, report schema/date/match errors
//	fendix ignore prune     — remove expired rules, write the file back in place
//
// Surfaces the suppression bookkeeping that was previously invisible:
// a user with 30 ignore rules accumulated over a year had no easy way
// to see which were about to expire, which were already dead weight,
// and which referenced findings that no longer exist. `list` + `prune`
// fix that without requiring a manual audit.
package ignorecmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/internal/cli"
	"github.com/Fendix-app/Fendix/go/internal/engine"
)

// defaultIgnorePath is the path checked when --file isn't passed.
// Matches the .fendix.yaml policy file's default-detect pattern from
// TASK-109: relative-to-cwd, no implicit walk-up.
const defaultIgnorePath = ".fendix-ignore"

// nearExpiryThreshold marks a rule as "expiring soon" in `list` so
// users can refresh them before they silently disappear. 30 days
// matches typical sprint-grooming cadence.
const nearExpiryThreshold = 30 * 24 * time.Hour

// NewCmd returns the `fendix ignore` cobra subcommand tree.
//
// The parent command is a no-op container: `fendix ignore` with no
// args prints usage. Subcommands (`list`, `validate`, `prune`) carry
// the actual behaviour.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ignore",
		Short: "Inspect and maintain .fendix-ignore",
		Long: "Inspect and maintain a .fendix-ignore suppression file.\n\n" +
			"Subcommands:\n" +
			"  list      Show all rules + expiry status\n" +
			"  validate  Parse the file and report errors\n" +
			"  prune     Remove expired rules and rewrite the file\n\n" +
			"All subcommands default to .fendix-ignore in the current directory;\n" +
			"pass --file <path> to target a different file.",
	}
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newValidateCmd())
	cmd.AddCommand(newPruneCmd())
	return cmd
}

// addFileFlag wires the shared --file flag onto a subcommand and
// returns a callable that resolves the user-supplied path (or the
// default).
func addFileFlag(cmd *cobra.Command) func() string {
	var path string
	cmd.Flags().StringVar(&path, "file", "", "Path to .fendix-ignore (default: ./.fendix-ignore)")
	return func() string {
		if path == "" {
			return defaultIgnorePath
		}
		return path
	}
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show every rule in .fendix-ignore with expiry status",
		Long: "Parse .fendix-ignore and print one row per rule:\n" +
			"  TARGET    — id / endpoint / category specifier\n" +
			"  EXPIRES   — date or '-' for permanent\n" +
			"  STATUS    — active / expiring-soon / EXPIRED / no-expiry\n" +
			"  REASON    — first 60 chars of the reason field\n\n" +
			"Rules expiring within 30 days are flagged 'expiring-soon' so they\n" +
			"can be refreshed before they silently stop suppressing.",
		Args: cobra.NoArgs,
	}
	getPath := addFileFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runList(cmd.OutOrStdout(), getPath())
	}
	return cmd
}

func runList(out io.Writer, path string) error {
	ig, err := engine.ParseIgnoreFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "no .fendix-ignore at %s\n", path)
			return nil
		}
		return fmt.Errorf("ignore list: %w", err)
	}
	if len(ig.Ignore) == 0 {
		fmt.Fprintf(out, "%s has no rules\n", path)
		return nil
	}

	now := time.Now()
	rows := make([]ignoreRow, 0, len(ig.Ignore))
	for _, r := range ig.Ignore {
		rows = append(rows, classifyRule(r, now))
	}
	// Stable order: expired first, then expiring-soon, then active.
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].statusRank < rows[j].statusRank
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tEXPIRES\tSTATUS\tREASON")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.target, row.expires, row.status, row.reason)
	}
	return tw.Flush()
}

// ignoreRow is the rendered form of an IgnoreRule for tabular display.
type ignoreRow struct {
	target     string
	expires    string
	status     string
	reason     string
	statusRank int // sort key; lower = print earlier
}

// classifyRule renders one rule for display + assigns a sort rank
// based on expiry status.
func classifyRule(r engine.IgnoreRule, now time.Time) ignoreRow {
	target := targetSummary(r)
	reason := truncateReason(r.Reason, 60)

	if r.Until == "" {
		return ignoreRow{target: target, expires: "-", status: "no-expiry", reason: reason, statusRank: 3}
	}

	expiry, err := time.Parse("2006-01-02", r.Until)
	if err != nil {
		return ignoreRow{target: target, expires: r.Until, status: "INVALID-DATE", reason: reason, statusRank: 0}
	}

	if now.After(expiry) {
		return ignoreRow{target: target, expires: r.Until, status: "EXPIRED", reason: reason, statusRank: 0}
	}
	if expiry.Sub(now) < nearExpiryThreshold {
		days := int(expiry.Sub(now).Hours() / 24)
		return ignoreRow{
			target:     target,
			expires:    r.Until,
			status:     fmt.Sprintf("expiring-soon (%dd)", days),
			reason:     reason,
			statusRank: 1,
		}
	}
	return ignoreRow{target: target, expires: r.Until, status: "active", reason: reason, statusRank: 2}
}

// targetSummary turns the (id | endpoint | category) tuple into a
// single-column display string. Prefers the most specific field
// present, falls back through endpoint → category → "(empty rule)".
func targetSummary(r engine.IgnoreRule) string {
	switch {
	case r.Fingerprint != "":
		return "fingerprint=" + r.Fingerprint
	case r.ID != "":
		return "id=" + r.ID
	case r.Endpoint != "" && r.Category != "":
		return fmt.Sprintf("%s [%s]", r.Endpoint, r.Category)
	case r.Endpoint != "":
		return r.Endpoint
	case r.Category != "":
		return "category=" + r.Category
	default:
		return "(empty rule)"
	}
}

// truncateReason trims a reason field for display, appending "..."
// when truncated. Empty reasons render as "(no reason)".
func truncateReason(reason string, max int) string {
	if reason == "" {
		return "(no reason)"
	}
	if len(reason) <= max {
		return reason
	}
	return reason[:max] + "..."
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse .fendix-ignore and report schema / date errors",
		Long: "Run the same parser the scanner uses on .fendix-ignore.\n" +
			"Reports YAML schema errors, invalid until-dates, and empty rules\n" +
			"(rules with no id/endpoint/category — they suppress nothing).\n" +
			"Exits 1 when any error is found; 0 when the file is clean.",
		Args: cobra.NoArgs,
	}
	getPath := addFileFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		errs, err := runValidate(cmd.OutOrStdout(), getPath())
		if err != nil {
			return err
		}
		if errs > 0 {
			// Exit 1, as the Long text above documents. A plain
			// fmt.Errorf would fall through main.go's generic error
			// path, which prints "Error: ..." on top of the per-error
			// lines runValidate already wrote and exits 2 — the code
			// reserved for "the tool could not produce a usable
			// result". *cli.ExitError carries the code explicitly and
			// main.go prints Message verbatim, with no prefix.
			return cli.ExitWithCode(1, fmt.Sprintf("%d validation error(s)", errs))
		}
		return nil
	}
	return cmd
}

func runValidate(out io.Writer, path string) (int, error) {
	ig, err := engine.ParseIgnoreFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "no .fendix-ignore at %s — nothing to validate\n", path)
			return 0, nil
		}
		// Parse error counts as a validation error itself.
		fmt.Fprintf(out, "ERROR  %s: %v\n", path, err)
		return 1, nil
	}

	errCount := 0
	for i, r := range ig.Ignore {
		if r.Fingerprint == "" && r.ID == "" && r.Endpoint == "" && r.Category == "" {
			fmt.Fprintf(out, "ERROR  rule #%d: empty rule (no fingerprint/id/endpoint/category — would suppress nothing)\n", i+1)
			errCount++
			continue
		}
		if r.Until != "" {
			if _, err := time.Parse("2006-01-02", r.Until); err != nil {
				fmt.Fprintf(out, "ERROR  rule #%d (%s): invalid until date %q (expected YYYY-MM-DD)\n",
					i+1, targetSummary(r), r.Until)
				errCount++
			}
		}
	}

	if errCount == 0 {
		fmt.Fprintf(out, "OK  %s — %d rule(s), no errors\n", path, len(ig.Ignore))
	}
	return errCount, nil
}

// ---------------------------------------------------------------------------
// prune
// ---------------------------------------------------------------------------

func newPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove expired rules and rewrite the file",
		Long: "Walk the .fendix-ignore rules, drop any whose until-date is in\n" +
			"the past, and rewrite the file in place.\n\n" +
			"Rules with no until-date or whose date is in the future are kept\n" +
			"as-is. Invalid until-dates are kept (run `fendix ignore validate`\n" +
			"first to surface those — we don't silently delete on a parse error).\n\n" +
			"Pass --dry-run to print what would be removed without writing.",
		Args: cobra.NoArgs,
	}
	getPath := addFileFlag(cmd)
	var dryRun bool
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be removed without writing")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runPrune(cmd.OutOrStdout(), getPath(), dryRun)
	}
	return cmd
}

// pruneWriter abstracts the file-write side of runPrune so tests can
// observe the proposed write without touching disk.
var pruneWriter = func(path string, ig *engine.IgnoreFile) error {
	data, err := yaml.Marshal(ig)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func runPrune(out io.Writer, path string, dryRun bool) error {
	ig, err := engine.ParseIgnoreFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "no .fendix-ignore at %s — nothing to prune\n", path)
			return nil
		}
		return fmt.Errorf("ignore prune: %w", err)
	}
	if len(ig.Ignore) == 0 {
		fmt.Fprintf(out, "%s has no rules — nothing to prune\n", path)
		return nil
	}

	now := time.Now()
	var kept []engine.IgnoreRule
	var dropped []engine.IgnoreRule
	for _, r := range ig.Ignore {
		if r.Until == "" {
			kept = append(kept, r)
			continue
		}
		expiry, err := time.Parse("2006-01-02", r.Until)
		if err != nil {
			// Don't silently drop rules with invalid dates — surface
			// them via `ignore validate` and let the user fix them.
			kept = append(kept, r)
			continue
		}
		if now.After(expiry) {
			dropped = append(dropped, r)
			continue
		}
		kept = append(kept, r)
	}

	if len(dropped) == 0 {
		fmt.Fprintf(out, "no expired rules — %d rule(s) kept\n", len(kept))
		return nil
	}

	for _, r := range dropped {
		fmt.Fprintf(out, "drop  %s (expired %s)\n", targetSummary(r), r.Until)
	}

	if dryRun {
		fmt.Fprintf(out, "\n(dry-run) would remove %d expired rule(s); pass without --dry-run to rewrite %s\n",
			len(dropped), path)
		return nil
	}

	ig.Ignore = kept
	if err := pruneWriter(path, ig); err != nil {
		return fmt.Errorf("ignore prune: write %s: %w", path, err)
	}
	fmt.Fprintf(out, "\nremoved %d expired rule(s); %d remaining in %s\n",
		len(dropped), len(kept), path)
	return nil
}
