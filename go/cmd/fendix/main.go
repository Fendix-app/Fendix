// Package main is the entrypoint for the Fendix CLI.
// Fendix is a hybrid API and code security scanner that combines
// black-box HTTP probing (Go) with white-box static analysis (Python).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/cli"
	"github.com/Abdel-RahmanSaied/Fendix/internal/democmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/engine"
	"github.com/Abdel-RahmanSaied/Fendix/internal/hookcmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/ignorecmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/initcmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/metrics"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/pluginscmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/policy"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"
	"github.com/Abdel-RahmanSaied/Fendix/internal/verifycmd"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	// Install a real slog default at startup. Without this,
	// `slog.Default()` returns the stdlib's *defaultHandler, which routes
	// through log.Default() → back to slog.Default(). Any code that wraps
	// the existing default (the --debug-bundle slog tee) would create
	// infinite recursion on every log call and deadlock on the log
	// package's mutex. Installing a concrete TextHandler here makes the
	// default a real, wrappable handler for every subcommand.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	start := time.Now()
	rootCmd := newRootCmd()
	// ExecuteC (not Execute) returns the command that actually ran, so the
	// CLI-success-rate metric can record WHICH subcommand was invoked.
	cmd, err := rootCmd.ExecuteC()

	// Release the temp dir the semgrep scanner extracted its embedded rule
	// pack into. Every command has finished by here, so nothing holds a
	// reference. Not a defer: the error paths below call os.Exit, which
	// skips defers — this must run on the failure paths too.
	if cleanupErr := semgrep.Cleanup(); cleanupErr != nil {
		slog.Warn("could not remove extracted semgrep rules", "error", cleanupErr)
	}

	// Record one phase="cli" event for every invocation — success OR failure
	// — so the success rate reflects real first-try outcomes (v0.25). Opt-in:
	// metrics.FromEnv is a no-op unless FENDIX_METRICS is set.
	code, class, success := classifyResult(cmd, err)
	recordCLIMetric(commandName(cmd), code, class, success, time.Since(start))

	if err != nil {
		// Sprint 03 introduced *cli.ExitError so subcommands can dictate a
		// specific, CI-script-friendly exit code. Catch and translate before
		// falling through to the generic error-prints-then-exit-2 path.
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}

		// Cobra's SilenceErrors=true on the root command suppresses its
		// built-in error printing (which clutters scan output), so we print
		// the error here ourselves before exiting. Without this, errors
		// from any subcommand vanish silently.
		fmt.Fprintln(os.Stderr, "Error:", err)
		// For a mistyped invocation (bad flag / wrong arg count), point the
		// user at the right help — but NOT for a runtime failure, where the
		// full usage block would just be noise. SilenceUsage stays on; this is
		// a single targeted line instead.
		if cmd != nil && isUsageError(err) {
			fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", cmd.CommandPath())
		}
		os.Exit(2)
	}
}

// commandName returns the leaf subcommand name for the metric, never the
// args. Falls back to "fendix" (e.g. an unknown-command error leaves cmd at
// the root) or "unknown" if cobra gave us nothing.
func commandName(cmd *cobra.Command) string {
	if cmd == nil {
		return "unknown"
	}
	return cmd.Name()
}

// classifyResult maps an Execute result to (exit code that main WILL use,
// coarse error class, success). Success convention: exit 0 = clean, exit 1 =
// the tool ran and reported a blocking/verification outcome (still a usable
// result), 2+ = the tool could not produce a usable result.
func classifyResult(cmd *cobra.Command, err error) (code int, class string, success bool) {
	if err == nil {
		return 0, "", true
	}
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.Code
	} else {
		code = 2
	}
	if code <= 1 {
		return code, "", true
	}
	switch {
	case isUsageError(err):
		class = "usage"
	case commandName(cmd) == "scan":
		class = "scan-error"
	default:
		class = "runtime"
	}
	return code, class, false
}

// isUsageError recognises cobra's flag/argument errors so they bucket as
// "usage" (the user mistyped the invocation) rather than a runtime failure.
func isUsageError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, sub := range []string{"unknown flag", "unknown shorthand", "unknown command", "invalid argument", "required flag", "accepts ", "flag needs an argument", "a scan target is required"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

// recordCLIMetric appends one CLI-invocation event. It is best-effort: a
// metrics write must never change the user's exit code, so errors are dropped.
func recordCLIMetric(command string, code int, class string, success bool, dur time.Duration) {
	c := metrics.FromEnv("")
	_ = c.Record(metrics.MetricEvent{
		Version:    Version,
		Phase:      "cli",
		DurationMs: dur.Milliseconds(),
		Timestamp:  time.Now().UTC(),
		Command:    command,
		ExitCode:   code,
		Success:    success,
		ErrorClass: class,
	})
	_ = c.Flush()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "fendix",
		Short: "Fendix — hybrid API and code security scanner",
		Long: `Fendix finds vulnerabilities before attackers do.

It combines black-box HTTP scanning with white-box static analysis
to produce high-confidence security findings with evidence.

Get started:
  fendix demo                          try Fendix on a built-in sample target
  fendix init                          set up Fendix in the current repo
  fendix scan --code . --fail-on HIGH  scan this repo, fail CI on HIGH and above`,
		SilenceUsage:               true,
		SilenceErrors:              true,
		SuggestionsMinimumDistance: 2,
		// Bare `fendix` shows help rather than a usage error (and is recorded
		// as a successful invocation, not a failure).
		Run: func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
	}

	// Surface the commands a newcomer needs first; everything else falls under
	// cobra's "Additional Commands:" so the top of `fendix --help` isn't a flat
	// 16-command dump.
	const groupCore = "core"
	root.AddGroup(&cobra.Group{ID: groupCore, Title: "Core commands:"})
	core := []func() *cobra.Command{newScanCmd, newInitCmd, newDemoCmd}
	for _, mk := range core {
		c := mk()
		c.GroupID = groupCore
		root.AddCommand(c)
	}

	root.AddCommand(newVersionCmd())
	root.AddCommand(newImportCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newNotifyCmd())
	root.AddCommand(newJiraCmd())
	root.AddCommand(newDBCmd())
	root.AddCommand(newEngineCmd())
	root.AddCommand(pluginscmd.NewCmd())
	root.AddCommand(ignorecmd.NewCmd())
	root.AddCommand(hookcmd.NewCmd())
	root.AddCommand(newBenchmarkCmd())
	root.AddCommand(newMetricsCmd())

	return root
}

func newDemoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Spin up OWASP Juice Shop locally and run a sample scan",
		Long: `Pull and start bkimminich/juice-shop in Docker on localhost:3000, run
a stock fendix scan against it, render an HTML report, and (with --open) open
the report in the default browser. Useful for first-time evaluators who want
to see a real Fendix scan without pointing it at production.

Cleans up the container on exit (success or failure).`,
		Example: `  fendix demo                       # scan, write report to $TMPDIR/fendix-demo-<unix>.html
  fendix demo --open                # also open the report in your browser
  fendix demo --port 4000           # bind juice-shop on a different port
  fendix demo --output ./demo.html  # write report to an explicit path`,
		RunE: func(cmd *cobra.Command, args []string) error {
			openAfter, _ := cmd.Flags().GetBool("open")
			port, _ := cmd.Flags().GetInt("port")
			output, _ := cmd.Flags().GetString("output")
			image, _ := cmd.Flags().GetString("image")

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			path, err := democmd.Run(ctx, democmd.Options{
				ImageRef:   image,
				Port:       port,
				OutputPath: output,
				OpenAfter:  openAfter,
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}
			_ = path // already printed by democmd.Run
			return nil
		},
	}
	cmd.Flags().Bool("open", false, "open the rendered HTML report in your default browser when the scan finishes")
	cmd.Flags().Int("port", democmd.DefaultPort, "local port to bind juice-shop on")
	cmd.Flags().String("output", "", "HTML report output path (default: $TMPDIR/fendix-demo-<unix>.html)")
	cmd.Flags().String("image", democmd.DefaultImageRef, "juice-shop Docker image reference (pinned for reproducibility)")
	return cmd
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a default CI workflow + .fendix-ignore in the current directory",
		Long: `Detect the project stack and write a drop-in CI workflow plus a
.fendix-ignore starter file. Refuses to overwrite existing files unless --force is set.

Pick a CI system via --ci. Without it, fendix auto-detects from .github/,
.gitlab-ci.yml, or .circleci/ in the project root, defaulting to GitHub when
none of those is present.

Files written (relative to the working directory):
  --ci github (default)  .github/workflows/fendix.yml   — PR-gated DAST+SAST scan
                         .fendix.yaml                   — policy starter
                         .fendix-ignore                 — finding suppressions
  --ci gitlab            .gitlab-ci.fendix.yml          — GitLab CI include file
                         NEXT-STEPS-fendix.md           — wiring instructions
                         .fendix.yaml + .fendix-ignore
  --ci circleci          .circleci/fendix-config.yml    — CircleCI snippet
                         NEXT-STEPS-fendix.md           — wiring instructions
                         .fendix.yaml + .fendix-ignore

Use --print to preview without writing.`,
		Example: `  fendix init                       # auto-detect CI; write the files
  fendix init --ci gitlab           # emit GitLab CI templates
  fendix init --ci circleci         # emit CircleCI templates
  fendix init --print               # preview the generated content
  fendix init --force               # overwrite existing files`,
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			print, _ := cmd.Flags().GetBool("print")
			ci, _ := cmd.Flags().GetString("ci")
			return initcmd.Run(initcmd.Options{
				Force: force,
				Print: print,
				CI:    ci,
				Out:   cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().Bool("force", false, "overwrite existing files")
	cmd.Flags().Bool("print", false, "print generated content to stdout instead of writing")
	cmd.Flags().String("ci", "", "CI system to emit templates for: github, gitlab, circleci (default: auto-detect → github)")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "fendix version %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

// runScan executes the scan pipeline. It is a package var purely as a test
// seam: it lets a test observe the context `scan` hands to the orchestrator
// (and assert it descends from cmd.Context()) without standing up a real
// scan. Production behaviour is the orchestrator call it wraps.
var runScan = func(ctx context.Context, cfg *models.ScanConfig, version string) int {
	return engine.NewOrchestrator(cfg, version).Run(ctx)
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a security scan",
		Long:  "Scan an API endpoint, source code, or both for security vulnerabilities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()

			urlFlag, _ := flags.GetString("url")
			specFlag, _ := flags.GetString("spec")
			codeFlag, _ := flags.GetString("code")
			authFlag, _ := flags.GetString("auth")
			authTypeFlag, _ := flags.GetString("auth-type")
			authHeaderFlag, _ := flags.GetString("auth-header")
			authUser2Flag, _ := flags.GetString("auth-user2")
			profileFlag, _ := flags.GetString("profile")
			outputFlag, _ := flags.GetString("output")
			formatFlag, _ := flags.GetString("format")
			failOnFlag, _ := flags.GetString("fail-on")
			baselineFlag, _ := flags.GetString("baseline")
			saveBaselineFlag, _ := flags.GetString("save-baseline")
			enableActive, _ := flags.GetBool("enable-active")
			maxProbesPerEndpoint, _ := flags.GetInt("max-probes-per-endpoint")
			workers, _ := flags.GetInt("workers")
			timeout, _ := flags.GetInt("timeout")
			delay, _ := flags.GetInt("delay")
			ignoreFlag, _ := flags.GetString("ignore")
			verbose, _ := flags.GetBool("verbose")
			wordlistFlag, _ := flags.GetString("wordlist")
			crawlDepth, _ := flags.GetInt("crawl-depth")
			maxEndpoints, _ := flags.GetInt("max-endpoints")
			maxRequests, _ := flags.GetInt64("max-requests")
			maxDuration, _ := flags.GetDuration("max-duration")
			respectRobots, _ := flags.GetBool("respect-robots")
			allowPrivateTargets, _ := flags.GetBool("allow-private-targets")
			debugBundleFlag, _ := flags.GetString("debug-bundle")
			managedEvidenceFlag, _ := flags.GetString("managed-evidence")
			managedContextFlag, _ := flags.GetString("managed-context")
			noPluginsFlag, _ := flags.GetBool("no-plugins")
			allowRepoLocalPluginsFlag, _ := flags.GetBool("allow-repo-local-plugins")
			noNativeDepsFlag, _ := flags.GetBool("no-native-deps")
			usePipAuditFlag, _ := flags.GetBool("use-pip-audit")
			pythonEngineFlag, _ := flags.GetBool("python-engine")
			// pythonEngineExplicit records that the user opted into SAST BY
			// NAME (--python-engine), as opposed to the implicit auto-enable
			// below. A missing engine is fatal only for the explicit case;
			// an implicit --code scan degrades to native-Go-only (see
			// ScanConfig.PythonEngineExplicit and orchestrator.Run).
			pythonEngineExplicit := flags.Changed("python-engine") && pythonEngineFlag
			// Auto-enable the Python engine for whitebox scans unless the
			// user explicitly disabled it. Without this, `fendix scan --code
			// <path>` runs only the native-Go checks and silently skips the
			// AST taint analyzer (injection / open-redirect / SSTI / path
			// traversal / unsafe-deserialize) entirely. When the engine isn't
			// discoverable for this implicit path, NewOrchestrator logs a WARN
			// and continues with the Go-only checks — it is NOT a hard error,
			// because the user didn't ask for SAST by name.
			if codeFlag != "" && !flags.Changed("python-engine") {
				pythonEngineFlag = true
			}
			configFlag, _ := flags.GetString("config")
			langFlag, _ := flags.GetString("lang")
			// --offline / --offline-db are registered below; read them into
			// ScanConfig so the orchestrator can run the dep-CVE scanners
			// against the local snapshot instead of osv.dev/vuln.go.dev
			// (F-M4/F-H4). --fail-on-scanner-error opts a CI run into a
			// non-zero exit on any recorded scanner failure (F-L7/F-L13).
			offlineFlag, _ := flags.GetBool("offline")
			offlineDBFlag, _ := flags.GetString("offline-db")
			failOnScannerErrorFlag, _ := flags.GetBool("fail-on-scanner-error")
			failOnCoverageGapFlag, _ := flags.GetBool("fail-on-coverage-gap")
			requireAnalyzersFlag, _ := flags.GetStringSlice("require-analyzers")
			if err := validateRequiredAnalyzers(requireAnalyzersFlag); err != nil {
				return cli.ExitWithCode(2, "fendix: "+err.Error())
			}
			// --diff enables diff-aware scanning. It's a string flag with a
			// NoOptDefVal of "HEAD", so bare `--diff` diffs against HEAD and
			// `--diff=origin/main` diffs against that ref. `flags.Changed`
			// tells us the user actually passed it (vs. the zero value).
			diffEnabled := flags.Changed("diff")
			diffRefFlag, _ := flags.GetString("diff")
			diffStagedFlag, _ := flags.GetBool("staged")
			// `--staged` implies diff mode even without an explicit --diff,
			// so a pre-commit hook can run `fendix scan --code . --staged`.
			if diffStagedFlag {
				diffEnabled = true
			}
			// The sentinel "HEAD" from NoOptDefVal means "no explicit ref" —
			// ChangedFiles treats an empty ref as "diff against HEAD", so
			// normalise it back to empty to keep the staged/unstaged default
			// (which must NOT pass a ref arg to git).
			if diffRefFlag == "HEAD" {
				diffRefFlag = ""
			}
			fastFlag, _ := flags.GetBool("fast")
			deescalateTestsFlag, _ := flags.GetBool("deescalate-tests")
			enforceConfidenceFlag, _ := flags.GetBool("enforce-confidence")
			blockOnInapplicableFlag, _ := flags.GetBool("block-on-inapplicable")
			checksFlag, _ := flags.GetStringSlice("checks")
			importFlag, _ := flags.GetStringSlice("import")

			// Resolve --config: explicit path takes precedence; if
			// absent and a .fendix.yaml exists in the cwd, pick it up
			// silently. Missing files are not errors — user might just
			// be running fendix without a policy.
			policyPath := configFlag
			if policyPath == "" {
				if _, err := os.Stat(policy.DefaultPath); err == nil {
					policyPath = policy.DefaultPath
				}
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fmt.Errorf("loading policy %s: %w", policyPath, err)
			}
			if configFlag != "" && pol == nil {
				// User explicitly pointed at a config file that doesn't
				// exist — refuse to silently fall back to flag-only.
				return fmt.Errorf("policy file not found: %s", configFlag)
			}

			if urlFlag == "" && specFlag == "" && codeFlag == "" {
				return fmt.Errorf("a scan target is required — provide at least one of:\n" +
					"  --code .                       scan source code in the current directory\n" +
					"  --url https://api.example.com  scan a running API\n" +
					"  --spec openapi.yaml            scan endpoints from an OpenAPI spec\n" +
					"or run 'fendix demo' to try Fendix on a built-in sample target")
			}

			cfg := &models.ScanConfig{
				URL:                   urlFlag,
				SpecPath:              specFlag,
				CodePath:              codeFlag,
				EnableActive:          enableActive,
				MaxProbesPerEndpoint:  maxProbesPerEndpoint,
				Workers:               workers,
				Timeout:               timeout,
				DelayMs:               delay,
				Verbose:               verbose,
				IgnorePath:            ignoreFlag,
				BaselinePath:          baselineFlag,
				SaveBaselinePath:      saveBaselineFlag,
				OutputPath:            outputFlag,
				Format:                formatFlag,
				FailOn:                failOnFlag,
				WordlistPath:          wordlistFlag,
				CrawlDepth:            crawlDepth,
				MaxEndpoints:          maxEndpoints,
				MaxRequests:           maxRequests,
				MaxDuration:           maxDuration,
				RespectRobots:         respectRobots,
				AllowPrivate:          allowPrivateTargets,
				DebugBundlePath:       debugBundleFlag,
				ManagedEvidencePath:   managedEvidenceFlag,
				ManagedContextPath:    managedContextFlag,
				NoPlugins:             noPluginsFlag,
				AllowRepoLocalPlugins: allowRepoLocalPluginsFlag,
				NoNativeDeps:          noNativeDepsFlag,
				UsePipAudit:           usePipAuditFlag,
				PythonEngine:          pythonEngineFlag,
				PythonEngineExplicit:  pythonEngineExplicit,
				Lang:                  resolveLang(langFlag, cmd.ErrOrStderr()),
				Offline:               offlineFlag,
				OfflineDBPath:         offlineDBFlag,
				FailOnScannerError:    failOnScannerErrorFlag,
				FailOnCoverageGap:     failOnCoverageGapFlag,
				RequiredAnalyzers:     requireAnalyzersFlag,
				Diff:                  diffEnabled,
				DiffRef:               diffRefFlag,
				DiffStaged:            diffStagedFlag,
				Fast:                  fastFlag,
				DeescalateTests:       deescalateTestsFlag,
				EnforceConfidence:     enforceConfidenceFlag,
				BlockOnInapplicable:   blockOnInapplicableFlag,
				Checks:                checksFlag,
				ImportPaths:           importFlag,
			}

			// Apply policy file values to cfg for fields the user did
			// NOT pass on the CLI. Precedence: cobra-default → policy
			// file → explicit CLI flag (CLI wins). The CLISet captures
			// which flags cobra observed as explicitly changed.
			if pol != nil {
				cli := policy.CLISet{}
				flags.Visit(func(f *pflag.Flag) { cli[f.Name] = true })
				appliedProfile := profileFlag
				applied := policy.ApplyTo{
					SetFailOn:        func(v string) { cfg.FailOn = v },
					SetEnableActive:  func(v bool) { cfg.EnableActive = v },
					SetWorkers:       func(v int) { cfg.Workers = v },
					SetTimeoutSec:    func(v int) { cfg.Timeout = v },
					SetDelayMs:       func(v int) { cfg.DelayMs = v },
					SetFormat:        func(v string) { cfg.Format = v },
					SetCrawlDepth:    func(v int) { cfg.CrawlDepth = v },
					SetMaxEndpoints:  func(v int) { cfg.MaxEndpoints = v },
					SetWordlistPath:  func(v string) { cfg.WordlistPath = v },
					SetRespectRobots: func(v bool) { cfg.RespectRobots = v },
					SetMaxRequests:   func(v int64) { cfg.MaxRequests = v },
					SetMaxDuration:   func(v time.Duration) { cfg.MaxDuration = v },
					SetIgnorePath:    func(v string) { cfg.IgnorePath = v },
					SetAuthProfile:   func(v string) { appliedProfile = v },

					SetDeescalateTests:   func(v bool) { cfg.DeescalateTests = v },
					SetEnforceConfidence: func(v bool) { cfg.EnforceConfidence = v },
				}.Run(pol, cli)
				if applied > 0 {
					slog.Info("policy applied", "path", policyPath, "fields", applied)
				}
				profileFlag = appliedProfile
			}

			var flagAuth *models.AuthContext
			if authFlag != "" {
				flagAuth = &models.AuthContext{
					Type:   authTypeFlag,
					Value:  authFlag,
					Header: authHeaderFlag,
				}
			}
			cfg.Auth = models.ResolveAuth(flagAuth, models.ProfileLoader(profileFlag))

			if authUser2Flag != "" {
				cfg.AuthUser2 = models.NormalizeAuth(&models.AuthContext{
					Value:  authUser2Flag,
					Header: authHeaderFlag,
				})
			}

			// Derive from cmd.Context() — NOT context.Background() — so an
			// embedder that drives the CLI via ExecuteContext can cancel the
			// scan and carry values down. Matches `demo` and `benchmark`.
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			exitCode := runScan(ctx, cfg, Version)
			if exitCode != 0 {
				// Route through main() (instead of os.Exit here) so deferred
				// cleanup runs and the CLI-success-rate metric is recorded for
				// scans too. Empty message → main prints nothing, just exits.
				return cli.ExitWithCode(exitCode, "")
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.String("url", "", "Target API base URL (black-box scanning)")
	flags.String("spec", "", "Path to OpenAPI/Swagger YAML or JSON spec")
	flags.String("code", "", "Path to source code directory (white-box scanning)")
	flags.String("auth", "", `Auth header value, e.g. "Bearer token123"`)
	flags.String("auth-type", "", "Auth type: bearer, apikey, basic, cookie (default: auto-detect)")
	flags.String("auth-header", "Authorization", "Custom auth header name")
	flags.String("auth-user2", "", `Second user auth for IDOR checks, e.g. "Bearer token-user2"`)
	flags.String("profile", "", "Auth profile name from ~/.fendix/profiles/<name>.yaml")
	flags.StringP("output", "o", "", "Output file path (default: stdout)")
	flags.StringP("format", "f", "json", "Output format: json, html, sarif, pdf")
	flags.String("fail-on", "", "Exit 1 if a CORROBORATED finding is at this severity: CRITICAL, HIGH, MEDIUM (confidence gating applies — see --enforce-confidence)")
	flags.String("baseline", "", "Path to previous findings JSON for diff mode")
	flags.String("save-baseline", "", "Save current findings to this path")
	flags.Bool("enable-active", false, "Enable active injection probes (default: false)")
	flags.Int("max-probes-per-endpoint", 20, "Max active probes per endpoint (only effective with --enable-active)")
	flags.IntP("workers", "w", 10, "Concurrent HTTP workers")
	flags.Int("timeout", 10, "HTTP timeout in seconds")
	flags.Int("delay", 100, "Milliseconds between HTTP requests")
	flags.String("ignore", "", "Path to .fendix-ignore file")
	flags.BoolP("verbose", "v", false, "Print all requests and raw findings")
	flags.String("wordlist", "", "Path to brute-force wordlist (one path per line); overrides built-in CommonPaths")
	flags.Int("crawl-depth", 1, "Recursive HTML link crawl depth (0 disables; 1 = home-page links only)")
	flags.Int("max-endpoints", 500, "Cap total discovered endpoints (0 = no cap)")
	flags.Int64("max-requests", 0, "Soft-cap on total HTTP requests across all checks (0 = no cap)")
	flags.Duration("max-duration", 0, "Soft-cap on total scan wall-clock time, e.g. 5m (0 = no cap)")
	flags.Bool("respect-robots", false, "Treat robots.txt Disallow as a hard restriction (default: queue as discovery hints)")
	flags.Bool("allow-private-targets", false, "Allow the scanner to connect to private/loopback/link-local addresses and the cloud metadata IP (disables the SSRF egress guard). Auto-enabled when --url already resolves to a private/loopback host.")
	flags.String("debug-bundle", "", "Write a redacted diagnostic tarball to this path at scan end (intended for bug reports)")
	// Managed CI (ADR-010). Both flags are set by the Fendix Action in managed
	// mode; a local run has no reason to use them.
	flags.String("managed-evidence", "", "Write the managed-CI submission document (contract managed-ci/v2) to this path. Requires --managed-context.")
	flags.String("managed-context", "", "Path to the runner-supplied managed-CI context (managed-scan-context/v1 plus evidence_submission_id).")
	flags.Bool("no-plugins", false, "Disable out-of-tree plugin discovery in .fendix/plugins/ + ~/.fendix/plugins/")
	flags.Bool("allow-repo-local-plugins", false, "Opt in to running repo-local plugins under <scan-dir>/.fendix/plugins/ (UNSAFE on untrusted PRs; ~/.fendix/plugins/ is always trusted)")
	flags.Bool("no-native-deps", false, "Disable the in-process Go dep-CVE scanner (TASK-119). Defer to the Python deps.py path instead.")
	flags.Bool("use-pip-audit", false, "Shell out to the pip-audit binary for Python dep-CVE scanning instead of the native OSV.dev client. Falls back to OSV.dev with a warning if pip-audit is not on PATH.")
	flags.Bool("python-engine", false, "Spawn the Python whitebox engine for auth/injection/deps checks (TASK-118). Default off — secrets and semgrep are now native Go and the embedded Python distribution is no longer bundled. Requires a local python/ source tree or FENDIX_ENGINE pointing at one.")
	flags.String("config", "", "Path to .fendix.yaml policy file (default: auto-detect .fendix.yaml in cwd)")
	flags.String("lang", "en", "HTML report language: en (default), ar (Arabic, RTL). Other formats stay English.")
	flags.Bool("offline", false, "Air-gapped mode: consult the local offline-db snapshot for dep CVEs instead of osv.dev/vuln.go.dev. The pip and npm scanners run against the snapshot (create it with `fendix db update`); govulncheck needs vuln.go.dev and is recorded SKIPPED. No outbound network call is made.")
	flags.String("offline-db", "", "Path to the offline-db snapshot (default: ~/.fendix/offline-db.json). Only effective with --offline.")
	flags.Bool("fail-on-scanner-error", false, "Exit non-zero (2) if any recorded analyzer — any entry in metadata.scanner_status, which is the full registry (dast, spec, active-probes, secrets, textscan, semgrep, govulncheck, pip, npm, plugins, the python-engine and its checks) — ran and errored. CI-friendly: turns a silent coverage gap into a build failure. Skipped entries never count.")
	flags.Bool("fail-on-coverage-gap", false, "Exit 2 when an analyzer this run was configured to execute was unavailable or failed (metadata.coverage.configured_complete=false). Disabled, not-applicable and unsupported analyzers never trip it.")
	flags.StringSlice("require-analyzers", nil, "Comma-separated analyzer names that must be delivered (recorded ok or not_applicable) for exit 0; anything else exits 2. Stricter than --fail-on-coverage-gap: a required analyzer disabled by another flag is a contradiction and exits 2. Names: "+strings.Join(engine.Registry, ", "))
	flags.Bool("block-on-inapplicable", false, "Gate the build on a vulnerable dependency even when Fendix found no import of the advisory's affected component. Default false: such a finding is reported in full and held at WARN, because the vulnerable code path is not applicable to this project on the available evidence. Set this when policy is \"no vulnerable version ships, applicable or not\" — e.g. where the SBOM is what gets audited rather than the call graph.")
	flags.Bool("deescalate-tests", true, "Report findings in test/fixture code as INFO instead of WARN (evidence is preserved, never suppressed). A finding at or above --fail-on still blocks when a corroborating signal backs it (e.g. a provider-validated live credential); an uncorroborated test-code match is held at WARN. Pass --deescalate-tests=false to treat test-code findings like production ones.")
	flags.Bool("enforce-confidence", true, "Only BLOCK a finding at or above --fail-on when the confidence band supports it AND something corroborates the claim: LOW band warns; a finding with no corroborating signal at all warns; MEDIUM band blocks only with an INDEPENDENT signal (cross-engine agreement, confirmed route, reachable taint path, proven path, payload-validated probe, cross-tool corroboration, contradicted authentication requirement); self-evident signals (direct response read, deterministic detection in production source, imported high-precision rule) gate at HIGH. Evidence is never suppressed. Pass --enforce-confidence=false to restore the legacy severity-only gate — findings that block only because of that relaxation are marked policy_override in the report.")
	flags.StringSlice("checks", nil, "Override which checks the Python whitebox engine runs (default: auth,injection,deps). Only effective with --python-engine; the native Go scanners (secrets/semgrep/textscan/deps) always run when --code is set.")
	// Diff-aware scanning (90-day cut, item 1). `--diff` alone diffs the
	// working tree against HEAD; `--diff=origin/main` against that ref;
	// `--staged` scopes to the index (what a pre-commit hook scans) and
	// implies diff mode. NoOptDefVal lets `--diff` work as a bare flag
	// while still accepting `--diff=<ref>`.
	flags.String("diff", "", "Diff-aware scan: only scan files changed vs a git ref (bare --diff = vs HEAD, --diff=origin/main = vs that ref). Whitebox scanners are scoped to the changed files; dep-CVE scanners run only when a manifest changed.")
	flags.Lookup("diff").NoOptDefVal = "HEAD"
	flags.Bool("staged", false, "Diff-aware scan over staged changes only (git diff --cached). Implies --diff. This is what the pre-commit hook runs.")
	flags.Bool("fast", false, "Fast mode: run only the instant native scanners (secrets + textscan), skipping semgrep (~1.5s startup) and the network dep-CVE scanners. Sub-second on a real monorepo; pairs with --staged for the pre-commit hook.")
	flags.StringSlice("import", nil, "Merge findings from another scanner's SARIF 2.1.0 file into this scan (repeatable). Imported findings go through the standard pipeline; a native fendix finding at the same weakness+location becomes strong cross-tool corroboration. See also the standalone 'fendix import' command.")

	return cmd
}

// validateRequiredAnalyzers rejects any --require-analyzers name that is
// not in the registry before a scan starts, so a typo cannot silently
// require nothing.
func validateRequiredAnalyzers(names []string) error {
	for _, n := range names {
		if !engine.IsRegisteredAnalyzer(n) {
			return fmt.Errorf("unknown analyzer %q in --require-analyzers; known analyzers: %s", n, strings.Join(engine.Registry, ", "))
		}
	}
	return nil
}

// resolveLang validates --lang against the i18n-supported set. Unknown
// values fall back to English with a one-line warning to stderr so the
// user can see their flag didn't take effect.
func resolveLang(lang string, stderr io.Writer) string {
	if lang == "" {
		return "en"
	}
	if reporters.IsSupportedLang(lang) {
		return lang
	}
	fmt.Fprintf(stderr, "warning: --lang=%q is not a supported translation; falling back to English. Supported: en, ar.\n", lang)
	return "en"
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render a saved findings file",
		Long:  "Convert a previously saved JSON findings file to HTML or SARIF format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			inputPath, _ := flags.GetString("input")
			formatFlag, _ := flags.GetString("format")
			outputPath, _ := flags.GetString("output")
			langFlag, _ := flags.GetString("lang")
			lang := resolveLang(langFlag, cmd.ErrOrStderr())

			if inputPath == "" {
				return fmt.Errorf("--input is required: path to a findings JSON file")
			}

			data, err := os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("reading input file %s: %w", inputPath, err)
			}

			report, err := reporters.ParseJSONReport(data)
			if err != nil {
				return fmt.Errorf("loading %s: %w", inputPath, err)
			}

			var w io.Writer = os.Stdout
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file %s: %w", outputPath, err)
				}
				defer f.Close()
				w = f
			}

			switch formatFlag {
			case "html":
				return reporters.RenderHTMLOpts(w, report.Findings, report.Metadata, reporters.HTMLOptions{Lang: lang})
			case "sarif":
				return reporters.RenderSARIF(w, report.Findings, report.Metadata)
			case "pdf":
				classification, _ := flags.GetString("classification")
				return reporters.RenderPDF(w, report.Findings, report.Metadata, reporters.PDFOptions{Classification: classification})
			case "json":
				return reporters.RenderJSON(w, report.Findings, report.Metadata)
			default:
				return fmt.Errorf("unsupported format %q — use json, html, sarif, or pdf", formatFlag)
			}
		},
	}

	flags := cmd.Flags()
	flags.String("input", "", "Path to findings JSON file")
	flags.StringP("format", "f", "html", "Output format: json, html, sarif, pdf")
	flags.StringP("output", "o", "", "Output file path (default: stdout)")
	flags.String("lang", "en", "HTML report language: en (default), ar (Arabic, RTL). Other formats stay English.")
	flags.String("classification", "INTERNAL", "PDF classification banner text rendered on every page (empty disables; only used by --format pdf)")

	return cmd
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [finding-id]",
		Short: "Re-run a single finding by ID and report still-present / resolved",
		Long: `Re-test a specific finding from a saved baseline scan report and
report whether it is still present, resolved, or unverifiable.

Supported finding shapes:
  - URL-anchored DAST findings    (source: blackbox)
  - File-anchored SAST findings   (source: whitebox; category:
                                   secrets / injection / headers / ...)
  - Dependency CVE findings       (category: deps)

Not yet supported (returns status "unknown" with an explanatory reason):
  - Correlated findings           (source: correlated)
  - Active injection probe findings (require --enable-active to reproduce)

Exit codes (Sprint 03 of the enterprise-readiness plan):
  0   resolved          — the finding no longer fires
  1   still-present     — the finding still fires; CI should fail the build
  2   unknown OR
      not-found-in-baseline
                        — verify could not produce a confident result;
                          the operator should investigate but CI should
                          NOT auto-fail on this

The user passes --baseline pointing at a previously saved findings.json
from "fendix scan --output ...", plus the same --url and/or --code that
the original scan used.

Output is JSON (machine-readable) when --json is set; otherwise a short
human-readable summary.

Use in CI:

  fendix verify SEC-001-abc --baseline scan.json --url $TARGET_URL
  case $? in
    0) echo "resolved";;
    1) echo "still present"; exit 1;;
    2) echo "verify could not tell — investigate manually";;
  esac
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			baseline, _ := cmd.Flags().GetString("baseline")
			targetURL, _ := cmd.Flags().GetString("url")
			codePath, _ := cmd.Flags().GetString("code")
			auth, _ := cmd.Flags().GetString("auth")
			emitJSON, _ := cmd.Flags().GetBool("json")
			timeoutSec, _ := cmd.Flags().GetInt("timeout")
			enableActive, _ := cmd.Flags().GetBool("enable-active")

			if baseline == "" {
				return fmt.Errorf("--baseline <findings.json> is required")
			}
			if targetURL == "" && codePath == "" {
				return fmt.Errorf("at least one of --url or --code must be set (matching the original scan)")
			}

			result, err := verifycmd.Run(cmd.Context(), args[0], verifycmd.Options{
				BaselinePath: baseline,
				URL:          targetURL,
				CodePath:     codePath,
				Auth:         auth,
				Timeout:      time.Duration(timeoutSec) * time.Second,
				EnableActive: enableActive,
			})
			if err != nil {
				return err
			}
			if err := verifycmd.Render(os.Stdout, result, emitJSON); err != nil {
				return err
			}

			// Exit-code semantics for CI scripting (Sprint 03).
			// 0 = resolved (default for RunE returning nil)
			// 1 = still-present (CI should fail the build)
			// 2 = unknown / not-found-in-baseline (operator should
			//     investigate but CI should not auto-fail)
			switch result.Status {
			case verifycmd.StatusResolved:
				return nil
			case verifycmd.StatusStillPresent:
				return cli.ExitWithCode(1, "finding still present")
			case verifycmd.StatusUnknown, verifycmd.StatusNotFound:
				return cli.ExitWithCode(2, fmt.Sprintf("verification %s", result.Status))
			default:
				return cli.ExitWithCode(2, fmt.Sprintf("unexpected status %q", result.Status))
			}
		},
	}
	cmd.Flags().String("baseline", "", "Path to the saved findings.json from the original scan (required)")
	cmd.Flags().String("url", "", "Target URL (re-test URL-anchored findings; same as original --url)")
	cmd.Flags().String("code", "", "Source code path (re-test file-anchored / dep findings; same as original --code)")
	cmd.Flags().String("auth", "", "Authorization header value (e.g. \"Bearer ...\")")
	cmd.Flags().Bool("json", false, "Emit JSON instead of the human-readable summary")
	cmd.Flags().Int("timeout", 15, "HTTP timeout in seconds (URL-anchored verify only)")
	cmd.Flags().Bool("enable-active", false, "Consent to re-send attack payloads when verifying an active-probe finding (mirrors the original scan's --enable-active)")
	return cmd
}
