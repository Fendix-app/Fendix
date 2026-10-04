package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/integrations/notify"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/spf13/cobra"
)

// newNotifyCmd wires the Sprint-15 notifier into the fendix CLI as a
// one-shot subcommand. The full flow is:
//
//	fendix scan ... --format json --output findings.json
//	export FENDIX_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
//	fendix notify --findings findings.json
//
// Designed to be embeddable in a CI step right after `scan` so the
// scan-and-alert split survives even before Sprint 07 lands a
// long-running serve. The subcommand reads its config from env vars
// (12-factor), matching `cmd/fendix-app/main.go`'s convention.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Post Slack / Teams alerts for findings above a severity floor",
		Long: `Read a findings JSON file (the output of ` + "`fendix scan --format json`" + `) and
post a Block Kit / Adaptive Card message per qualifying finding to one or
both incoming-webhook URLs.

Configuration is via environment variables (12-factor):

  FENDIX_SLACK_WEBHOOK_URL    Slack incoming-webhook URL.
                              https://hooks.slack.com/services/...
  FENDIX_TEAMS_WEBHOOK_URL    Teams incoming-webhook URL.
  FENDIX_NOTIFY_MIN_SEVERITY  Floor for alerts: CRITICAL, HIGH, MEDIUM,
                              LOW, INFO. Default: CRITICAL.
  FENDIX_NOTIFY_DEDUP_WINDOW  Go duration (e.g. "30m", "2h") suppressing
                              repeat alerts on the same finding ID.
                              Default: 1h. Set to 0 to disable dedup.

At least one webhook URL must be set; otherwise the subcommand exits
with a clear "no webhook configured" error. Per-finding sink failures
are logged but do not fail the whole invocation — one broken Slack
webhook doesn't suppress the Teams alert.`,
		Example: `  fendix notify --findings findings.json
  FENDIX_NOTIFY_MIN_SEVERITY=HIGH fendix notify --findings findings.json
  FENDIX_NOTIFY_DEDUP_WINDOW=0 fendix notify --findings findings.json   # disable dedup`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("findings")
			if path == "" {
				return errors.New("--findings is required (path to a findings JSON produced by `fendix scan --format json`)")
			}
			timeout, _ := cmd.Flags().GetDuration("timeout")
			return runNotify(cmd.Context(), cmd.OutOrStdout(), path, timeout)
		},
	}
	cmd.Flags().String("findings", "", "Path to a findings JSON file produced by 'fendix scan --format json'")
	cmd.Flags().Duration("timeout", 30*time.Second, "Overall timeout for posting all webhooks")
	return cmd
}

// runNotify is split out so tests can drive it directly.
func runNotify(ctx context.Context, w io.Writer, findingsPath string, timeout time.Duration) error {
	n, err := notify.NewFromEnv()
	if err != nil {
		if errors.Is(err, notify.ErrEmptyConfig) {
			return fmt.Errorf("%w. Set FENDIX_SLACK_WEBHOOK_URL or FENDIX_TEAMS_WEBHOOK_URL", err)
		}
		return err
	}

	data, err := os.ReadFile(findingsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", findingsPath, err)
	}
	findings, err := parseFindings(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", findingsPath, err)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ notify: zero findings in the input file; nothing to post.")
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	postCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := n.NotifyAll(postCtx, findings)

	sent, skipped, errored := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Sent:
			sent++
		case r.Err != nil:
			errored++
			fmt.Fprintf(w, "✗ notify: %s sink failed for finding %q: %v\n", r.Sink, r.Finding, r.Err)
		case r.Skipped != "":
			skipped++
		}
	}
	fmt.Fprintf(w, "✓ notify: sent=%d skipped=%d errored=%d\n", sent, skipped, errored)
	if errored > 0 && sent == 0 {
		// All sink attempts errored — return non-zero so CI scripts see
		// the failure. Partial success (some sent + some errored) still
		// exits 0; the per-error log line is enough for operator review.
		return fmt.Errorf("notify: all %d webhook posts errored", errored)
	}
	return nil
}

// parseFindings accepts two on-wire shapes for findings JSON:
//   - the full scan-report envelope (with .findings) that `fendix scan
//     --format json` emits;
//   - a bare top-level array of Finding objects (matching the report's
//     .findings field) for callers who pre-extract it via jq or similar.
func parseFindings(data []byte) ([]models.Finding, error) {
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
