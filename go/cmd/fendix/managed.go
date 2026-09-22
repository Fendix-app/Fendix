package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/cli"
	"github.com/Abdel-RahmanSaied/Fendix/internal/managedci"
	"github.com/spf13/cobra"
)

// `fendix managed submit` is the managed-CI transport: it POSTs the evidence
// document the scan produced and waits for the BACKEND's decision.
//
// Why this is a CLI command and not shell in the Action: the token stays in
// one process that reads it from the environment and puts it in exactly one
// header. It never reaches argv (visible in `ps` to anything on the runner),
// a shell trace, a log line or a summary. The polling envelope, the retry
// set and the fail-closed rules are then testable Go rather than untested
// bash.
//
// Exit contract:
//
//	0  the backend decided, and the decision does not fail the gate
//	1  the backend decided, and the decision fails the gate (BLOCK/INCOMPLETE)
//	2  no decision was obtained — never treated as a pass
const tokenEnv = "FENDIX_CI_TOKEN" //nolint:gosec // the NAME of the variable, not a credential

func newManagedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "managed",
		Short: "Managed CI: submit evidence and take the backend's decision",
		Long: "Managed mode sends sanitized evidence to the Fendix backend, which decides. " +
			"The runner never computes, infers or falls back to a local decision.",
	}
	cmd.AddCommand(newManagedContextCmd())
	cmd.AddCommand(newManagedSubmitCmd())
	return cmd
}

// `fendix managed context` builds the managed-scan context from the GitHub
// workflow environment. It exists so the identities the backend checks are
// read from the environment and the event payload by code that is tested,
// rather than assembled by shell in the Action — and so head_sha is the pull
// request's head commit, not the ephemeral merge commit GITHUB_SHA names.
func newManagedContextCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "context",
		Short:        "Write the managed-scan context for this workflow run",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmd.Flags()
			tenant, _ := flags.GetString("tenant-id")
			asset, _ := flags.GetString("asset-id")
			environment, _ := flags.GetString("environment")
			out, _ := flags.GetString("out")
			if out == "" {
				return fmt.Errorf("managed context requires --out")
			}
			runner, err := managedci.ContextFromEnv(os.Getenv, managedci.Binding{
				TenantID: tenant, AssetID: asset, Environment: environment,
			})
			if err != nil {
				return err
			}
			if err := managedci.WriteContext(out, runner); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "managed context written for %s\n", out)
			return nil
		},
	}
	flags := cmd.Flags()
	flags.String("tenant-id", "", "Organization (tenant) UUID from the Fendix binding")
	flags.String("asset-id", "", "Asset UUID from the Fendix binding")
	flags.String("environment", "", "sandbox, staging or production — must match the credential")
	flags.String("out", "", "Path to write the context to")
	return cmd
}

func newManagedSubmitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit managed evidence and wait for the authoritative decision",
		Long: "POST the document written by `fendix scan --managed-evidence` and poll until the " +
			"backend reaches a terminal state. The credential is read from " + tokenEnv +
			"; it is never accepted as a flag, so it cannot appear in argv or a process listing.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmd.Flags()
			evidencePath, _ := flags.GetString("evidence")
			apiBase, _ := flags.GetString("api-base")
			decisionPath, _ := flags.GetString("decision-output")
			timeout, _ := flags.GetDuration("timeout")

			token := strings.TrimSpace(os.Getenv(tokenEnv))
			if token == "" {
				return fmt.Errorf("managed submission requires %s in the environment", tokenEnv)
			}
			if evidencePath == "" {
				return fmt.Errorf("managed submission requires --evidence")
			}
			if !strings.HasPrefix(apiBase, "https://") && !strings.HasPrefix(apiBase, "http://127.0.0.1") &&
				!strings.HasPrefix(apiBase, "http://localhost") {
				// A credential must not travel in clear text; the two local
				// forms exist so the pilot can be exercised end to end.
				return fmt.Errorf("--api-base must be an https origin")
			}
			body, err := os.ReadFile(evidencePath)
			if err != nil {
				return fmt.Errorf("read managed evidence: %w", err)
			}

			client := managedci.NewClient(apiBase, token)
			if timeout > 0 {
				client.Timeout = timeout
			}
			ctx := cmd.Context()
			started := time.Now()
			submitted, err := client.Submit(ctx, body)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "evidence accepted: submission %s\n", submitted.EvidenceSubmissionID)

			decision, err := client.Await(ctx, client.StatusURL(submitted))
			if err != nil {
				return err
			}
			if decisionPath != "" {
				encoded, marshalErr := json.MarshalIndent(decision, "", "  ")
				if marshalErr == nil {
					_ = os.WriteFile(decisionPath, append(encoded, '\n'), 0o600)
				}
			}
			report(cmd, decision, time.Since(started))
			if decision.FailGate {
				// Exit 1 means "the backend decided, and its decision fails
				// the gate" — distinct from exit 2, which means no decision
				// was obtained at all. The gate is the BACKEND's; the local
				// scan's own exit code played no part in reaching it.
				return &cli.ExitError{
					Code: 1,
					Message: fmt.Sprintf("Fendix: the backend decision is %s — see decision record %s",
						decision.Decision, decision.Record.DecisionRecordID),
				}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.String("evidence", "", "Path to the document written by `fendix scan --managed-evidence`")
	flags.String("api-base", "https://api.fendix.dev", "Backend API origin")
	flags.String("decision-output", "", "Write the authoritative decision to this path")
	flags.Duration("timeout", managedci.DefaultDecisionTimeout, "Total budget for obtaining a decision")
	return cmd
}

func report(cmd *cobra.Command, decision *managedci.Decision, elapsed time.Duration) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "backend decision: %s (coverage %s, policy %s, %s)\n",
		decision.Decision, decision.CoverageState, decision.BackendPolicyVersion, elapsed.Round(time.Millisecond))
	if len(decision.ReasonCodes) > 0 {
		fmt.Fprintf(out, "reasons: %s\n", strings.Join(decision.ReasonCodes, ", "))
	}
	fmt.Fprintf(out, "decision record: %s\n", decision.Record.DecisionRecordID)
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		writeStepSummary(summary, decision)
	}
	if outputs := os.Getenv("GITHUB_OUTPUT"); outputs != "" {
		writeStepOutputs(outputs, decision)
	}
}

// writeStepOutputs publishes the backend's decision as Action outputs, so a
// workflow can read it without parsing JSON in shell. Only the decision and
// its record reference are published — never a local result.
func writeStepOutputs(path string, decision *managedci.Decision) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	_, _ = fmt.Fprintf(file, "decision=%s\ndecision-record=%s\n",
		sanitizeOutput(decision.Decision), sanitizeOutput(decision.Record.DecisionRecordID))
}

// sanitizeOutput keeps a server-controlled value from injecting extra lines
// into the outputs file.
func sanitizeOutput(value string) string {
	return strings.NewReplacer("\n", "", "\r", "", "=", "").Replace(value)
}

// writeStepSummary renders the BACKEND's decision for the job summary. It
// writes the decision, its reasons and the record reference — no token, no
// local verdict and no finding content.
func writeStepSummary(path string, decision *managedci.Decision) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	var summary strings.Builder
	summary.WriteString("## Fendix managed decision\n\n")
	summary.WriteString(fmt.Sprintf("**%s** — coverage %s, backend policy %s\n\n",
		decision.Decision, decision.CoverageState, decision.BackendPolicyVersion))
	if len(decision.ReasonCodes) > 0 {
		summary.WriteString("Reasons: `" + strings.Join(decision.ReasonCodes, "`, `") + "`\n\n")
	}
	summary.WriteString(fmt.Sprintf("Decision record `%s` (revision %d)\n",
		decision.Record.DecisionRecordID, decision.Record.Revision))
	_, _ = file.WriteString(summary.String())
}
