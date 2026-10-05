package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/integrations/jira"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/spf13/cobra"
)

// newJiraCmd wires the Sprint-14 Jira sync as a one-shot CLI
// subcommand. Designed to slot into a CI step right after `scan`:
//
//	fendix scan ... --format json --output findings.json
//	export FENDIX_JIRA_URL=https://your-org.atlassian.net
//	export FENDIX_JIRA_PROJECT_KEY=SEC
//	export FENDIX_JIRA_EMAIL=you@example.com
//	export FENDIX_JIRA_API_TOKEN=<token>
//	fendix jira --findings findings.json
//
// Each finding above FENDIX_JIRA_MIN_SEVERITY (default HIGH) gets a
// Jira issue with a `fendix-id:<id>` label. The next run with the
// same findings is idempotent — no duplicate issues.
func newJiraCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jira",
		Short: "Sync findings to Jira as Bug issues (idempotent via fendix-id label)",
		Long: `Read a findings JSON file (the output of ` + "`fendix scan --format json`" + `) and
create one Jira issue per finding above a severity floor. Each issue
carries a fendix-id:<finding.ID> label as the idempotency key — a
second run with the same findings creates no duplicates.

Configuration is via environment variables (12-factor):

  FENDIX_JIRA_URL            https://your-org.atlassian.net
  FENDIX_JIRA_PROJECT_KEY    e.g. "SEC"
  FENDIX_JIRA_EMAIL          Jira account email
  FENDIX_JIRA_API_TOKEN      Jira API token (atlassian.com → Profile → Security → API tokens)
  FENDIX_JIRA_MIN_SEVERITY   CRITICAL | HIGH | MEDIUM | LOW | INFO. Default: HIGH.
  FENDIX_JIRA_ISSUE_TYPE     Default: "Bug". Override for projects that use "Task" or "Vulnerability".

URL, ProjectKey, Email, and APIToken are all required.

Auto-resolution of issues whose findings stop appearing in subsequent
scans is a follow-up (Sprint 14.5) — it requires a stable persistence
story to know "this scan is the latest", which depends on Sprint 07.5
(SQLite). Today the subcommand is create-or-skip only.`,
		Example: `  fendix jira --findings findings.json
  FENDIX_JIRA_MIN_SEVERITY=CRITICAL fendix jira --findings findings.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("findings")
			if path == "" {
				return errors.New("--findings is required (path to a findings JSON produced by `fendix scan --format json`)")
			}
			timeout, _ := cmd.Flags().GetDuration("timeout")
			strict, _ := cmd.Flags().GetBool("strict")
			return runJira(cmd.Context(), cmd.OutOrStdout(), path, timeout, strict)
		},
	}
	cmd.Flags().String("findings", "", "Path to a findings JSON file produced by 'fendix scan --format json'")
	cmd.Flags().Duration("timeout", 5*time.Minute, "Overall timeout for the Jira sync")
	cmd.Flags().Bool("strict", false, "Exit non-zero if ANY finding fails to sync (default: exit non-zero only when every finding fails)")
	return cmd
}

func runJira(ctx context.Context, w io.Writer, findingsPath string, timeout time.Duration, strict bool) error {
	c, err := jira.NewFromEnv()
	if err != nil {
		if errors.Is(err, jira.ErrEmptyConfig) {
			return fmt.Errorf("%w. Set FENDIX_JIRA_URL, FENDIX_JIRA_PROJECT_KEY, FENDIX_JIRA_EMAIL, and FENDIX_JIRA_API_TOKEN", err)
		}
		return err
	}

	data, err := os.ReadFile(findingsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", findingsPath, err)
	}
	findings, err := parseFindingsForJira(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", findingsPath, err)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ jira: zero findings in the input file; nothing to sync.")
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	syncCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := c.SyncFindings(syncCtx, findings)
	if err != nil {
		return fmt.Errorf("sync findings: %w", err)
	}

	fmt.Fprintf(w, "✓ jira: created=%d unchanged=%d skipped=%d errored=%d\n",
		len(result.Created), len(result.Unchanged), len(result.Skipped), len(result.Errors))
	for _, k := range result.Created {
		fmt.Fprintf(w, "  + %s\n", k)
	}
	for _, e := range result.Errors {
		fmt.Fprintf(w, "  ! %s\n", e.Error())
	}
	if strict && len(result.Errors) > 0 {
		return fmt.Errorf("jira: %d finding(s) failed to sync (--strict)", len(result.Errors))
	}
	if len(result.Errors) > 0 && len(result.Created) == 0 && len(result.Unchanged) == 0 {
		return fmt.Errorf("jira: every finding failed (%d errors)", len(result.Errors))
	}
	return nil
}

// parseFindingsForJira accepts either the full scan-report envelope
// (`{"findings": [...]}` shape produced by `fendix scan --format
// json`) or a bare top-level array. Same shape-tolerance as the
// notify subcommand, intentionally — both consume the same upstream.
func parseFindingsForJira(data []byte) ([]models.Finding, error) {
	var envelope struct {
		Findings []models.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Findings != nil {
		return envelope.Findings, nil
	}
	var bare []models.Finding
	if err := json.Unmarshal(data, &bare); err != nil {
		return nil, err
	}
	return bare, nil
}
