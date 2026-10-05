// Package pluginscmd implements the `fendix plugins …` cobra
// subcommand tree introduced in TASK-130 / Phase 17c.
//
// Two subcommands:
//
//	fendix plugins list                  — enumerate discovered plugins
//	fendix plugins install <git-url>     — clone a plugin repo into
//	                                       ~/.fendix/plugins/<name>/
//
// `install` is intentionally a thin wrapper over `git clone`: the
// engine doesn't introduce a "plugin registry" concept, doesn't
// build a marketplace, and doesn't broker trust between author and
// user. The community installs plugins by URL and trusts what they
// install. The registry-style flow is a Q3 candidate per
// docs/example_plan.md.
//
// `list` reads the same discovery roots Discover() walks during a
// scan, so what's printed is exactly what would run.
package pluginscmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Fendix-app/Fendix/go/internal/plugin"
)

// NewCmd returns the `fendix plugins` cobra subcommand tree.
//
// The parent command is a no-op container: `fendix plugins` with no
// args prints usage. Subcommands (`list`, `install`) carry the
// actual behaviour.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage out-of-tree plugins",
		Long: "Manage Fendix plugins discovered under ~/.fendix/plugins/ (user-global,\n" +
			"trusted) and — only with --allow-repo-local-plugins — the repo-local\n" +
			".fendix/plugins/ (opt-in; the scanned repo is attacker-controlled in CI).\n\n" +
			"Subcommands:\n" +
			"  list                 Show every plugin the scanner would discover\n" +
			"  install <git-url>    Clone a plugin repo into the user-global root\n\n" +
			"Plugins extend Fendix with custom checks via the same NDJSON wire\n" +
			"contract the embedded engine uses (ADR-002). See docs/plugins.md\n" +
			"for the authoring guide.",
	}
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newInstallCmd())
	return cmd
}

// newListCmd returns the `fendix plugins list` subcommand.
//
// Walks the same default roots Discover() uses for a real scan and
// prints a table: NAME, VERSION, MODE, DIR. Exit code is always 0;
// an empty discovery returns "no plugins found" on stdout, not an
// error. This is informational tooling, not a CI gate.
func newListCmd() *cobra.Command {
	var allowRepoLocal bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every plugin the scanner would discover",
		Long: "Walk ~/.fendix/plugins/ (and, with --allow-repo-local-plugins, the\n" +
			"repo-local .fendix/plugins/ in the current directory) and print each\n" +
			"plugin's name, version, mode, and on-disk directory.\n\n" +
			"The walk order mirrors what a 'fendix scan' invocation does, so\n" +
			"what this command prints is exactly what would run. By default the\n" +
			"repo-local root is NOT searched (F-H2): the scanned repo is\n" +
			"attacker-controlled in CI. Pass --allow-repo-local-plugins to include\n" +
			"it, matching the same flag on 'fendix scan'. A repo-local plugin with\n" +
			"the same name as a user-global one shadows it (only the winning entry\n" +
			"is shown).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("plugins list: resolve cwd: %w", err)
			}
			roots := plugin.DefaultRoots(cwd, allowRepoLocal)
			plugins, err := plugin.Discover(roots)
			if err != nil {
				return fmt.Errorf("plugins list: discover: %w", err)
			}

			out := cmd.OutOrStdout()

			if len(plugins) == 0 {
				fmt.Fprintln(out, "no plugins found")
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Discovery roots checked (in order):")
				for _, r := range roots {
					fmt.Fprintf(out, "  - %s\n", r)
				}
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Install a plugin with `fendix plugins install <git-url>`")
				fmt.Fprintln(out, "or copy a plugin directory into one of the roots above.")
				return nil
			}

			// Stable sort by name so output is deterministic across runs.
			sort.Slice(plugins, func(i, j int) bool {
				return plugins[i].Name < plugins[j].Name
			})

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tVERSION\tMODE\tDIR")
			for _, p := range plugins {
				version := p.Version
				if version == "" {
					version = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, version, p.Mode, p.Dir)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&allowRepoLocal, "allow-repo-local-plugins", false,
		"Include repo-local .fendix/plugins/ in the listing (UNSAFE on untrusted PRs; off by default)")
	return cmd
}

// validInstallURL accepts only the transports we trust to feed into
// `git clone`. Git supports several local/remote schemes that can
// invoke arbitrary commands on a malicious URL — `file://` reads
// arbitrary paths the user has access to, `ext::` runs a helper
// program named in the URL, etc. The official upstream advisory is
// CVE-2017-1000117 and the family of follow-ups.
//
// The allowlist below is the set of transports a community plugin
// repo would realistically advertise:
//
//   - https://<host>/<path>           — GitHub, GitLab, self-hosted
//   - http://<host>/<path>            — only for explicit dev/test
//   - git://<host>/<path>             — read-only git transport
//   - ssh://[user@]<host>[:port]/path — SSH git, full URL form
//   - <user>@<host>:<path>            — SCP-style git URL (`git@github.com:org/repo.git`)
//
// Everything else is rejected with an actionable error pointing the
// user at this comment. Tests cover the rejection paths.
var (
	validInstallURLSchemeRe = regexp.MustCompile(`^(https?|git|ssh)://`)
	validInstallURLScpRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[A-Za-z0-9_./-]+$`)
)

func validateInstallURL(gitURL string) error {
	u := strings.TrimSpace(gitURL)
	if u == "" {
		return fmt.Errorf("git URL is empty")
	}
	if validInstallURLSchemeRe.MatchString(u) {
		return nil
	}
	if validInstallURLScpRe.MatchString(u) {
		return nil
	}
	return fmt.Errorf("git URL %q uses an unsupported transport — accepted forms are https://…, http://…, git://…, ssh://…, or scp-style user@host:path (file://, ext::, and other git transports are rejected because they can execute arbitrary commands)", gitURL)
}

// validInstallNameRe locks the directory name we derive from a
// remote URL to a safe subset: alnum + dash + underscore + dot, no
// path separators, no leading dot. Catches dorky URLs like
// `…/../etc/passwd` before they hit os.MkdirAll.
var validInstallNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// newInstallCmd returns the `fendix plugins install <git-url>` subcommand.
//
// The flow:
//
//  1. Resolve target = ~/.fendix/plugins/<derived-name>/
//  2. Refuse if target already exists (no implicit upgrade — that's
//     the user's job; `rm -rf` it themselves if they want to replace)
//  3. Shell out to `git clone --depth=1 <git-url> <target>`
//  4. Validate the cloned tree has a parseable plugin.yaml
//  5. On validation failure, remove the cloned directory so we don't
//     leave a half-installed plugin that the scanner would skip with
//     a WARN every time.
//
// The git binary is required on PATH. We don't statically link a git
// implementation (go-git is large + has surprising defaults around
// authentication); shelling out to system git matches what
// internal/ghapp already does for PR checkout.
func newInstallCmd() *cobra.Command {
	var nameOverride string
	cmd := &cobra.Command{
		Use:   "install <git-url>",
		Short: "Clone a plugin repo into ~/.fendix/plugins/",
		Long: "Clone a remote plugin repository into the user-global plugin root\n" +
			"(~/.fendix/plugins/<name>/) and verify it has a valid plugin.yaml.\n\n" +
			"The on-disk name is derived from the URL by default (strip the\n" +
			"trailing .git and take the last path component). Override with\n" +
			"--name when the upstream name conflicts with another installed\n" +
			"plugin or is non-portable.\n\n" +
			"Examples:\n" +
			"  fendix plugins install https://github.com/you/my-fendix-plugin\n" +
			"  fendix plugins install git@github.com:you/my-fendix-plugin.git --name custom-x\n\n" +
			"Requirements:\n" +
			"  - git on $PATH\n" +
			"  - Network access to the remote\n" +
			"  - Target ~/.fendix/plugins/<name>/ must not already exist\n" +
			"    (run 'rm -rf' yourself to replace an installed plugin)",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gitURL := args[0]
			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()
			return runInstall(out, errOut, gitURL, nameOverride)
		},
	}
	cmd.Flags().StringVar(&nameOverride, "name", "",
		"Override the on-disk directory name (defaults to the repo's last path component)")
	return cmd
}

// gitClone wraps exec.Command("git", "clone", …) so tests can stub
// the subprocess call without spinning up a real network round-trip.
// Returns the combined stderr (the only stream git writes
// human-readable output to) for the error path.
var gitClone = func(srcURL, destDir string) ([]byte, error) {
	cmd := exec.Command("git", "clone", "--depth=1", srcURL, destDir)
	return cmd.CombinedOutput()
}

// userPluginsRoot returns ~/.fendix/plugins. Var-not-func so tests
// can point install at a tmpdir.
var userPluginsRoot = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".fendix", "plugins"), nil
}

// loadPlugin validates the manifest after clone. Var-not-func so
// tests can substitute a no-op without writing a real plugin.yaml.
var loadPluginFn = plugin.LoadPlugin

// runInstall is the install body, split out so tests can drive it
// without going through cobra.
func runInstall(out, errOut io.Writer, gitURL, nameOverride string) error {
	if err := validateInstallURL(gitURL); err != nil {
		return fmt.Errorf("plugins install: %w", err)
	}

	name := nameOverride
	if name == "" {
		name = deriveName(gitURL)
	}
	if !validInstallNameRe.MatchString(name) {
		return fmt.Errorf("plugins install: derived name %q contains invalid characters; pass --name to override", name)
	}

	root, err := userPluginsRoot()
	if err != nil {
		return fmt.Errorf("plugins install: %w", err)
	}
	// 0o700 not 0o755 — plugin code runs as the current user and may
	// read scan-time profile credentials; other local users have no
	// business enumerating which plugins this user has installed.
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("plugins install: create %s: %w", root, err)
	}

	dest := filepath.Join(root, name)
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("plugins install: %s already exists (rm -rf it first to replace)", dest)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("plugins install: stat %s: %w", dest, err)
	}

	fmt.Fprintf(out, "Cloning %s into %s...\n", gitURL, dest)
	if output, err := gitClone(gitURL, dest); err != nil {
		// git's stderr is the only useful diagnostic; surface it.
		trimmed := strings.TrimSpace(string(output))
		if len(trimmed) > 400 {
			trimmed = trimmed[:400] + "..."
		}
		return fmt.Errorf("plugins install: git clone failed: %v\n%s", err, trimmed)
	}

	// Validate the cloned tree — clean up on failure so we never
	// leave a half-installed plugin that would WARN every scan.
	p, err := loadPluginFn(dest)
	if err != nil {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("plugins install: cloned tree is not a valid plugin: %w (removed %s)", err, dest)
	}

	fmt.Fprintf(out, "✓ Installed plugin %s (mode=%s, version=%s)\n", p.Name, p.Mode, p.Version)
	fmt.Fprintf(out, "  Location: %s\n", dest)
	fmt.Fprintf(out, "  Run `fendix plugins list` to confirm; run a scan to invoke it.\n")
	return nil
}

// deriveName turns a git URL into a directory name. Strategy:
//
//	https://github.com/you/my-plugin       → my-plugin
//	https://github.com/you/my-plugin.git   → my-plugin
//	git@github.com:you/my-plugin.git       → my-plugin
//	file:///tmp/foo/                       → foo
//
// We strip any trailing slash, the .git suffix, and take the
// basename. validInstallNameRe rejects anything that comes out
// looking weird, so the caller will be told to pass --name.
func deriveName(gitURL string) string {
	// Trim query strings, fragments, trailing slashes.
	url := gitURL
	if i := strings.IndexAny(url, "?#"); i >= 0 {
		url = url[:i]
	}
	url = strings.TrimRight(url, "/")
	url = strings.TrimSuffix(url, ".git")

	// scp-style git URLs use ':' as the host/path separator.
	if !strings.Contains(url, "://") {
		if i := strings.LastIndex(url, ":"); i >= 0 {
			url = url[i+1:]
		}
	}

	// Take the last path segment.
	if i := strings.LastIndex(url, "/"); i >= 0 {
		url = url[i+1:]
	}
	return url
}
