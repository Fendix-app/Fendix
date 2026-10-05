// Package plugin discovers and runs out-of-tree Fendix plugins.
//
// A plugin is a directory containing a plugin.yaml manifest and an
// executable entrypoint. The engine invokes the entrypoint with a
// JSON ScanRequest on stdin; the entrypoint emits zero or more
// newline-delimited Finding JSON objects on stdout, terminated by
// {"done": true, "total": N}. This is the same NDJSON contract the
// embedded Python engine speaks (ADR-002), so plugin authors writing
// a Python plugin can share most of the engine.py scaffolding.
//
// Discovery walks two roots in order:
//
//  1. <repo>/.fendix/plugins/    (repo-local; OPT-IN — see below)
//  2. ~/.fendix/plugins/         (user-global; trusted)
//
// On collision (same plugin name in both roots) the repo-local
// version wins, so a project can pin a specific plugin version
// without affecting the developer's other repos.
//
// Repo-local plugins are NOT auto-discovered by default (F-H2): a
// repository under scan is attacker-controlled in the poisoned-
// pipeline threat model (a malicious PR can drop a `.fendix/plugins/`
// directory and get arbitrary code executed in CI). The repo-local
// root is therefore gated behind explicit opt-in (the
// AllowRepoLocalPlugins config flag, threaded into Roots). The
// user-global ~/.fendix/plugins root the operator populated by hand
// stays trusted and is always searched.
package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// envAllowlist is the fixed set of operator env var names a plugin
// subprocess inherits. A plugin runs arbitrary third-party code at
// the operator's privilege; inheriting the full operator environment
// gives plugin code trivial access to credentials it has no business
// reading. An *allowlist* (rather than the older substring denylist,
// FX-PLUG-2 / F-I1) fails closed: a credential in a variable nobody
// anticipated — `SNYK_TOKEN`, `VAULT_ADDR`, a bespoke `MY_CREDS` —
// is dropped because it isn't on the list, instead of surviving
// because no denylist entry happened to match its name.
//
// The list is deliberately minimal: just what a plugin needs to find
// its interpreter and behave like a well-mannered CLI process. The
// FENDIX_PLUGIN_* vars Run sets explicitly are always passed through
// (they're appended after redaction, not inherited). Plugins that
// need an extra var can declare it in the manifest's optional `env:`
// allowlist — see Spec.Env and redactPluginEnv.
var envAllowlist = map[string]struct{}{
	"PATH":   {}, // find the interpreter + child tools
	"HOME":   {}, // language runtimes resolve config/cache relative to it
	"LANG":   {}, // locale; harmless and some tools mis-encode without it
	"TMPDIR": {}, // scratch space; many runtimes honour it
}

// envAllowlistPrefixes lists name *prefixes* that are passed through
// in addition to the exact-match envAllowlist. LC_* covers the POSIX
// locale category vars (LC_ALL, LC_CTYPE, …) and FENDIX_PLUGIN_*
// covers the vars Run injects (kept here so a manifest can't be
// tricked into shadowing them and so the allowlist is self-describing).
var envAllowlistPrefixes = []string{
	"LC_",
	"FENDIX_PLUGIN_",
}

// redactPluginEnv returns the operator's environment filtered down to
// the allowlist: an entry survives only if its *name* is in
// envAllowlist, matches an envAllowlistPrefixes prefix, or is named in
// the optional per-plugin extra allowlist (the manifest's `env:`
// field; pass nil for none). The match is case-sensitive on the
// variable's name, not its value.
//
// Exported via a package-level var so tests can verify behaviour
// without spawning a subprocess.
func redactPluginEnv(env []string, extra []string) []string {
	allowExtra := make(map[string]struct{}, len(extra))
	for _, name := range extra {
		allowExtra[name] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			// Malformed (no '=' or leading '='); Go's os.Environ never
			// produces these, but if a caller hand-builds one, drop it —
			// it can't be matched against the allowlist by name.
			continue
		}
		name := kv[:eq]
		if envNameAllowed(name, allowExtra) {
			out = append(out, kv)
		}
	}
	return out
}

// envNameAllowed reports whether an env var name passes the allowlist
// (fixed set + prefix set + the per-plugin extra set).
func envNameAllowed(name string, extra map[string]struct{}) bool {
	if _, ok := envAllowlist[name]; ok {
		return true
	}
	if _, ok := extra[name]; ok {
		return true
	}
	for _, p := range envAllowlistPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// DefaultTimeout caps a single plugin invocation when the manifest
// does not specify a Timeout.
const DefaultTimeout = 30 * time.Second

// MaxTimeout is the upper bound on plugin runtime regardless of what
// the manifest claims. A plugin that wants longer scans should run
// async and emit findings incrementally; the engine cannot wait
// forever on a single subprocess.
const MaxTimeout = 5 * time.Minute

// Mode declares whether a plugin sees blackbox (URL/spec/auth) or
// whitebox (code path) inputs. Plugins that need both can declare
// Mode="hybrid"; the orchestrator will run them once with all fields
// populated.
type Mode string

const (
	ModeBlackbox Mode = "blackbox"
	ModeWhitebox Mode = "whitebox"
	ModeHybrid   Mode = "hybrid"
)

// Spec is the on-disk plugin.yaml schema. Unknown fields are
// rejected (yaml.Decoder.KnownFields(true)) so typos surface as
// errors rather than silently-ignored config — same posture as
// .fendix.yaml in policy.Load.
type Spec struct {
	Name        string        `yaml:"name"`
	Version     string        `yaml:"version,omitempty"`
	Description string        `yaml:"description,omitempty"`
	Entrypoint  string        `yaml:"entrypoint"`
	Mode        Mode          `yaml:"mode"`
	Categories  []string      `yaml:"categories,omitempty"`
	Timeout     time.Duration `yaml:"timeout,omitempty"`
	// Env is an optional allowlist of extra environment variable names
	// the plugin needs passed through from the operator's environment
	// (F-I1). By default the runner inherits only a minimal fixed
	// allowlist (PATH, HOME, LANG/LC_*, TMPDIR) plus the FENDIX_PLUGIN_*
	// vars it sets; a plugin that needs, say, a corporate proxy var can
	// name it here. This is the plugin author *requesting* a var — it
	// does not grant access the operator hasn't already exported.
	// Backwards-compatible: omitting it preserves the minimal default.
	Env []string `yaml:"env,omitempty"`
}

// Plugin is a discovered, validated plugin ready to run.
type Plugin struct {
	Spec
	// Dir is the absolute path to the plugin directory. Entrypoint
	// is resolved relative to Dir.
	Dir string
}

// ScanRequest is the JSON payload the engine sends to a plugin's
// stdin. It mirrors the embedded engine's ScanRequest plus a
// Categories field so plugins can filter to relevant work without
// re-walking the source tree. Field names are stable — adding new
// fields is fine, removing or renaming them is a breaking change.
type ScanRequest struct {
	Mode       Mode     `json:"mode"`
	URL        string   `json:"url,omitempty"`
	Spec       string   `json:"spec,omitempty"`
	CodePath   string   `json:"code_path,omitempty"`
	Auth       string   `json:"auth,omitempty"`
	AuthType   string   `json:"auth_type,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Verbose    bool     `json:"verbose"`
}

// doneMessage matches the engine's terminator format so plugin
// authors with an existing engine.py-shaped plugin work unchanged.
type doneMessage struct {
	Done  bool   `json:"done"`
	Total int    `json:"total"`
	Error string `json:"error,omitempty"`
}

// Discover walks the given roots in order, parses every plugin.yaml
// it finds, and returns the resulting Plugin list deduplicated by
// Name (earlier roots win — pass repo-local first, user-global
// second; see DefaultRoots). A malformed plugin.yaml in one directory
// does not stop discovery in others; the error for that directory is
// logged at WARN level and the plugin is skipped.
//
// Symlinked plugin *directories* are skipped (F-H2): following a
// symlink lets a directory entry point outside the discovery root —
// a poisoned repo could symlink its `.fendix/plugins/x` at an
// attacker-staged tree, and an operator's `~/.fendix/plugins/y` could
// be redirected by a hostile package. Only real directories are
// discovered; copy (or `git clone`) a plugin into the root rather
// than symlinking it.
//
// Discover is intentionally tolerant of missing roots: a fresh
// install with no plugin directories returns ([], nil), not an error.
func Discover(roots []string) ([]Plugin, error) {
	seen := make(map[string]struct{})
	var out []Plugin
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			slog.Warn("plugin discovery: cannot read root", "root", root, "err", err)
			continue
		}
		for _, e := range entries {
			dir := filepath.Join(root, e.Name())
			// Lstat (not Stat) so a symlinked entry reports as a symlink
			// rather than its target. Symlinked plugin directories are
			// skipped: following them lets a discovery-root entry escape
			// the root (F-H2). Real directories only.
			info, err := os.Lstat(dir)
			if err != nil {
				slog.Debug("plugin entry unstable", "dir", dir, "err", err)
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				slog.Warn("plugin skipped: symlinked plugin directory not followed", "dir", dir)
				continue
			}
			if !info.IsDir() {
				continue
			}
			p, err := loadPlugin(dir)
			if err != nil {
				slog.Warn("plugin skipped", "dir", dir, "err", err)
				continue
			}
			if _, dup := seen[p.Name]; dup {
				slog.Debug("plugin shadowed by earlier root", "name", p.Name, "dir", dir)
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

// LoadPlugin parses plugin.yaml under dir and validates the result.
// Exported wrapper around loadPlugin so the `fendix plugins install`
// subcommand (internal/pluginscmd, TASK-130) can validate a freshly-
// cloned tree without re-implementing the manifest parser.
func LoadPlugin(dir string) (Plugin, error) {
	return loadPlugin(dir)
}

// loadPlugin parses plugin.yaml under dir and validates the result.
func loadPlugin(dir string) (Plugin, error) {
	manifest := filepath.Join(dir, "plugin.yaml")
	f, err := os.Open(manifest)
	if err != nil {
		return Plugin{}, fmt.Errorf("open plugin.yaml: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return Plugin{}, fmt.Errorf("parse plugin.yaml: %w", err)
	}

	if err := validate(&s); err != nil {
		return Plugin{}, err
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return Plugin{}, fmt.Errorf("absolute path: %w", err)
	}
	return Plugin{Spec: s, Dir: abs}, nil
}

func validate(s *Spec) error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("plugin.yaml: name is required")
	}
	if strings.ContainsAny(s.Name, "/\\") {
		return fmt.Errorf("plugin.yaml: name %q must not contain path separators", s.Name)
	}
	if strings.TrimSpace(s.Entrypoint) == "" {
		return errors.New("plugin.yaml: entrypoint is required")
	}
	if filepath.IsAbs(s.Entrypoint) {
		return fmt.Errorf("plugin.yaml: entrypoint %q must be relative to the plugin directory", s.Entrypoint)
	}
	if strings.Contains(s.Entrypoint, "..") {
		return fmt.Errorf("plugin.yaml: entrypoint %q must not traverse with '..'", s.Entrypoint)
	}
	switch s.Mode {
	case ModeBlackbox, ModeWhitebox, ModeHybrid:
	case "":
		return errors.New("plugin.yaml: mode is required (blackbox, whitebox, or hybrid)")
	default:
		return fmt.Errorf("plugin.yaml: mode %q is not one of blackbox, whitebox, hybrid", s.Mode)
	}
	if s.Timeout < 0 {
		return fmt.Errorf("plugin.yaml: timeout %s must not be negative", s.Timeout)
	}
	if s.Timeout > MaxTimeout {
		return fmt.Errorf("plugin.yaml: timeout %s exceeds engine cap of %s", s.Timeout, MaxTimeout)
	}
	return nil
}

// Run invokes the plugin entrypoint and returns the findings it
// emitted. A plugin that exits with non-zero status, takes longer
// than its timeout, or emits a {"error": ...} terminator returns
// an error; partial findings collected before the failure are
// preserved in the slice.
//
// Findings emitted without a Source field are tagged with the
// plugin's Mode so downstream correlation/dedup treats them
// consistently with the embedded engines.
func (p Plugin) Run(ctx context.Context, req ScanRequest) ([]models.Finding, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Re-validate the on-disk entrypoint just before exec (F-H2): the
	// manifest parse rejected `..`/absolute paths, but the resolved
	// path and its in-dir parent chain can still be a symlink escaping
	// the plugin dir, group/other-writable, or owned by another uid —
	// all of which let a second party swap the code we're about to run
	// (TOCTOU on a shared/CI checkout). Best-effort on non-Unix.
	entrypoint := filepath.Join(p.Dir, p.Entrypoint)
	if err := checkEntrypointSafe(p.Dir, entrypoint); err != nil {
		return nil, fmt.Errorf("plugin %s: %w", p.Name, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, entrypoint)
	cmd.Dir = p.Dir
	// Filter the inherited environment down to a minimal allowlist
	// before handing it to third-party code (see envAllowlist + Spec.Env
	// for the policy and rationale). FENDIX_PLUGIN_* are appended below,
	// not inherited.
	cmd.Env = append(redactPluginEnv(os.Environ(), p.Env),
		"FENDIX_PLUGIN_NAME="+p.Name,
		"FENDIX_PLUGIN_DIR="+p.Dir,
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %s: stdin pipe: %w", p.Name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %s: stdout pipe: %w", p.Name, err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("plugin %s: start: %w", p.Name, err)
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("plugin %s: marshal request: %w", p.Name, err)
	}
	// EPIPE from stdin.Write means the plugin exited before reading the
	// request — a valid contract for plugins that emit findings without
	// needing input (e.g. a static-scan plugin that ignores ScanRequest).
	// Fall through to read stdout and let the exit-code + readPluginFindings
	// terminator be authoritative. Other write errors (transport-level)
	// are still fatal.
	if _, err := stdin.Write(append(reqJSON, '\n')); err != nil && !errors.Is(err, io.ErrClosedPipe) && !isBrokenPipe(err) {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("plugin %s: write request: %w", p.Name, err)
	}
	_ = stdin.Close()

	findings, readErr := readPluginFindings(stdout, p)
	waitErr := cmd.Wait()

	if stderrBuf.Len() > 0 {
		slog.Debug("plugin stderr", "plugin", p.Name, "stderr", strings.TrimSpace(stderrBuf.String()))
	}

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return findings, fmt.Errorf("plugin %s: timeout after %s", p.Name, timeout)
	}
	if readErr != nil {
		return findings, fmt.Errorf("plugin %s: %w", p.Name, readErr)
	}
	if waitErr != nil {
		return findings, fmt.Errorf("plugin %s: exit: %w", p.Name, waitErr)
	}
	return findings, nil
}

// readPluginFindings drains the plugin's stdout, returning the
// findings array and any terminator error (e.g. plugin emitted
// {"error": "..."}). Malformed lines are skipped at DEBUG level
// rather than raising — a single junk line on stdout shouldn't
// fail the whole scan.
func readPluginFindings(r io.Reader, p Plugin) ([]models.Finding, error) {
	var out []models.Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var done doneMessage
		if err := json.Unmarshal([]byte(line), &done); err == nil && done.Done {
			if done.Error != "" {
				return out, fmt.Errorf("plugin reported error: %s", done.Error)
			}
			return out, nil
		}

		var f models.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			slog.Debug("plugin emitted malformed JSON", "plugin", p.Name, "line", line, "err", err)
			continue
		}
		if f.Title == "" || f.Severity == "" {
			slog.Debug("plugin finding missing required fields", "plugin", p.Name, "line", line)
			continue
		}
		if f.Source == "" {
			f.Source = sourceForMode(p.Mode)
		}
		// Tag the finding with the plugin name so reports/dedup can
		// trace provenance. We piggy-back on References because
		// adding a new top-level field would break the IPC contract.
		f.References = append(f.References, "fendix-plugin:"+p.Name)
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scan plugin stdout: %w", err)
	}
	return out, nil
}

func sourceForMode(m Mode) models.Source {
	switch m {
	case ModeBlackbox:
		return models.SourceBlackbox
	case ModeWhitebox, ModeHybrid:
		return models.SourceWhitebox
	default:
		return models.SourceWhitebox
	}
}

// DefaultRoots returns the canonical plugin search path. The
// user-global root (~/.fendix/plugins) is always included — the
// operator populated it by hand, so it's trusted. The repo-local root
// (<cwd>/.fendix/plugins) is included only when allowRepoLocal is true
// (F-H2): the scanned repo is attacker-controlled in the poisoned-
// pipeline threat model, so a `.fendix/plugins/` committed by a
// hostile PR must not auto-execute in CI. When repo-local is allowed,
// it's listed first so it shadows a same-named user-global plugin.
//
// cwd is the working directory whose .fendix/plugins should be
// searched (typically the scan root). If cwd is empty, the repo-local
// root is omitted regardless of allowRepoLocal. On systems where
// os.UserHomeDir fails (very rare) the user-global root is silently
// omitted.
func DefaultRoots(cwd string, allowRepoLocal bool) []string {
	var roots []string
	if allowRepoLocal && cwd != "" {
		roots = append(roots, filepath.Join(cwd, ".fendix", "plugins"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".fendix", "plugins"))
	}
	return roots
}

// isBrokenPipe reports whether err is a write-to-closed-pipe failure,
// which happens when a plugin exits before reading our ScanRequest on
// stdin. A fast-exiting plugin that emits all its findings without
// needing input is a valid contract (e.g. a static-scan plugin that
// ignores ScanRequest entirely), so we tolerate EPIPE on stdin.Write
// and let stdout + exit-code be authoritative.
func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EPIPE)
}
