// Package hookcmd implements the `fendix hook …` cobra subcommand tree
// (90-day cut, item 2). It installs a git pre-commit hook that runs a
// fast, staged, diff-aware scan on every commit — the second half of the
// "runs on every commit" developer-workflow story, after `fendix scan
// --diff --staged` (item 1).
//
//	fendix hook install     — write .git/hooks/pre-commit
//	fendix hook uninstall    — remove the fendix-managed hook
//	fendix hook status       — report whether the hook is installed
//
// The installed hook runs:
//
//	fendix scan --code . --staged --fast --fail-on <severity>
//
// --staged scopes the scan to the index and --fast skips Semgrep and native
// dependency scanners. Known product defect: because --code auto-enables the
// Python phase, the generated command is not currently native-only and can run
// the Python deps check. A finding at or above --fail-on aborts the commit only
// when the decision policy stamps it BLOCK; the developer fixes it (or bypasses
// with `git commit --no-verify`).
//
// Safety: install refuses to clobber a pre-existing non-fendix pre-commit
// hook unless --force is passed, and never silently overwrites the user's
// own automation. The hook is marked with a sentinel comment so status /
// uninstall can recognise it.
package hookcmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// hookSentinel marks a pre-commit file as fendix-managed so `status` and
// `uninstall` can recognise it and `install` knows it is safe to replace.
const hookSentinel = "# fendix-managed-pre-commit-hook"

// defaultFailOn is the severity at which the hook aborts a commit. HIGH (not
// CRITICAL) because the whole point of a commit-time gate is to stop serious
// issues — a hardcoded secret is HIGH/CRITICAL — before they enter history.
const defaultFailOn = "HIGH"

// NewCmd builds the `fendix hook` subcommand tree.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage the git pre-commit hook that runs a fast diff scan",
		Long: "Install or remove a git pre-commit hook that runs " +
			"`fendix scan --staged --fast` on every commit, aborting the " +
			"commit if a finding at or above the chosen severity reaches BLOCK. " +
			"Known limitation: --fast does not disable the Python phase auto-enabled by --code.",
	}
	cmd.AddCommand(newInstallCmd())
	cmd.AddCommand(newUninstallCmd())
	cmd.AddCommand(newStatusCmd())
	return cmd
}

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the fendix pre-commit hook into the current git repo",
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			failOn, _ := cmd.Flags().GetString("fail-on")
			return runInstall(cmd, force, failOn)
		},
	}
	cmd.Flags().Bool("force", false, "Overwrite an existing non-fendix pre-commit hook")
	cmd.Flags().String("fail-on", defaultFailOn, "Decision threshold: CRITICAL, HIGH, MEDIUM, LOW; the hook aborts only when a finding reaches BLOCK")
	return cmd
}

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the fendix-managed pre-commit hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd)
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the fendix pre-commit hook is installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd)
		},
	}
}

// hooksDir resolves the git hooks directory, honouring core.hooksPath (which
// teams using husky/pre-commit/lefthook often set) and worktrees. Falls back
// to <git-common-dir>/hooks. Returns an error when not inside a git repo.
func hooksDir() (string, error) {
	// `git rev-parse --git-path hooks` resolves core.hooksPath, worktrees,
	// and the common dir in one call — the canonical way to find where a
	// hook must live. Older git lacks --git-path hooks resolution of
	// core.hooksPath, so we also consult the config explicitly.
	if custom, err := gitConfig("core.hooksPath"); err == nil && custom != "" {
		abs := custom
		if !filepath.IsAbs(abs) {
			if top, terr := gitRevParse("--show-toplevel"); terr == nil {
				abs = filepath.Join(top, custom)
			}
		}
		return abs, nil
	}
	p, err := gitRevParse("--git-path", "hooks")
	if err != nil {
		return "", err
	}
	// --git-path returns a path relative to the cwd; make it absolute so
	// the written hook location is unambiguous in the success message.
	if !filepath.IsAbs(p) {
		if abs, aerr := filepath.Abs(p); aerr == nil {
			p = abs
		}
	}
	return p, nil
}

func runInstall(cmd *cobra.Command, force bool, failOn string) error {
	// The threshold is written into the hook; an invalid one would make
	// every commit fail with a usage error. Refuse it here instead.
	failOn, err := models.ParseFailOn(failOn)
	if err != nil {
		return err
	}
	dir, err := hooksDir()
	if err != nil {
		return fmt.Errorf("not a git repository (run inside a repo, or `git init` first): %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating hooks dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "pre-commit")

	// Refuse to clobber a hook we didn't write, unless --force.
	if existing, rerr := os.ReadFile(path); rerr == nil {
		if !bytes.Contains(existing, []byte(hookSentinel)) && !force {
			return fmt.Errorf(
				"a pre-commit hook already exists at %s and is not fendix-managed.\n"+
					"Re-run with --force to replace it, or add this line to your hook manually:\n"+
					"    %s",
				path, hookCommand(failOn))
		}
	}

	script := hookScript(failOn)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		return fmt.Errorf("writing hook %s: %w", path, err)
	}
	// WriteFile honours umask; force the exec bits so the hook is runnable
	// regardless of the user's umask.
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("chmod hook %s: %w", path, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"✓ Installed fendix pre-commit hook at %s\n  Runs on every commit: %s\n  Bypass once with: git commit --no-verify\n",
		path, hookCommand(failOn))
	return nil
}

func runUninstall(cmd *cobra.Command) error {
	dir, err := hooksDir()
	if err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}
	path := filepath.Join(dir, "pre-commit")
	existing, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			fmt.Fprintln(cmd.OutOrStdout(), "No pre-commit hook installed — nothing to do.")
			return nil
		}
		return fmt.Errorf("reading hook %s: %w", path, rerr)
	}
	if !bytes.Contains(existing, []byte(hookSentinel)) {
		return fmt.Errorf("the pre-commit hook at %s is not fendix-managed; leaving it untouched", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing hook %s: %w", path, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed fendix pre-commit hook at %s\n", path)
	return nil
}

func runStatus(cmd *cobra.Command) error {
	dir, err := hooksDir()
	if err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}
	path := filepath.Join(dir, "pre-commit")
	existing, rerr := os.ReadFile(path)
	switch {
	case os.IsNotExist(rerr):
		fmt.Fprintln(cmd.OutOrStdout(), "fendix pre-commit hook: not installed")
	case rerr != nil:
		return fmt.Errorf("reading hook %s: %w", path, rerr)
	case bytes.Contains(existing, []byte(hookSentinel)):
		fmt.Fprintf(cmd.OutOrStdout(), "fendix pre-commit hook: installed at %s\n", path)
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "pre-commit hook present at %s but NOT fendix-managed\n", path)
	}
	return nil
}

// hookCommand is the single fendix invocation the hook runs. Kept in one
// place so install/status messaging and the script body never drift.
func hookCommand(failOn string) string {
	return fmt.Sprintf("fendix scan --code . --staged --fast --fail-on %s", failOn)
}

// hookScript renders the full pre-commit script. It is intentionally a
// small, dependency-free POSIX sh script: it resolves the fendix binary
// (preferring one on PATH, falling back to the absolute path of the binary
// that installed the hook so a venv/PATH change can't silently disable the
// gate), then runs the staged fast scan.
func hookScript(failOn string) string {
	self := selfPath()
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString(hookSentinel + "\n")
	b.WriteString("# Installed by `fendix hook install`. Runs a fast, staged,\n")
	b.WriteString("# diff-aware scan on every commit. Remove with `fendix hook uninstall`.\n")
	b.WriteString("# Bypass a single commit with: git commit --no-verify\n")
	b.WriteString("set -e\n\n")
	b.WriteString("# Prefer fendix on PATH; fall back to the binary that installed this hook.\n")
	b.WriteString("FENDIX_BIN=\"$(command -v fendix 2>/dev/null || true)\"\n")
	if self != "" {
		b.WriteString(fmt.Sprintf("if [ -z \"$FENDIX_BIN\" ] && [ -x %q ]; then\n", self))
		b.WriteString(fmt.Sprintf("  FENDIX_BIN=%q\n", self))
		b.WriteString("fi\n")
	}
	b.WriteString("if [ -z \"$FENDIX_BIN\" ]; then\n")
	b.WriteString("  echo 'fendix: binary not found on PATH; skipping pre-commit scan' >&2\n")
	b.WriteString("  exit 0\n")
	b.WriteString("fi\n\n")
	b.WriteString(fmt.Sprintf("exec \"$FENDIX_BIN\" scan --code . --staged --fast --fail-on %s\n", failOn))
	return b.String()
}

// selfPath returns the absolute path of the running fendix binary, or "" if
// it can't be resolved. Embedded into the hook as a PATH-independent
// fallback so a developer who installed via an absolute path keeps a working
// hook even when fendix isn't on the committing shell's PATH.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if abs, aerr := filepath.Abs(exe); aerr == nil {
		return abs
	}
	return exe
}

// --- git plumbing (os/exec, matching the codebase's no-go-git stance) ---

var execCommand = exec.Command

func gitRevParse(args ...string) (string, error) {
	return runGit(append([]string{"rev-parse"}, args...)...)
}

func gitConfig(key string) (string, error) {
	return runGit("config", "--get", key)
}

func runGit(args ...string) (string, error) {
	cmd := execCommand("git", args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(out.String()), nil
}
