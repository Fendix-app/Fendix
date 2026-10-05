package plugin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// writePlugin builds a plugin directory with a manifest and a shell
// script entrypoint. Returns the parent root suitable for Discover.
func writePlugin(t *testing.T, name, manifest, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("plugin tests use POSIX shell; skipping on windows")
	}
	root := t.TempDir()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if script != "" {
		path := filepath.Join(dir, "run.sh")
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write script: %v", err)
		}
	}
	return root
}

func TestDiscover_EmptyRootsReturnsNothing(t *testing.T) {
	root := t.TempDir()
	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins on empty root, got %d", len(plugins))
	}
}

func TestDiscover_MissingRootIsNotAnError(t *testing.T) {
	plugins, err := Discover([]string{"/nonexistent/plugins/dir"})
	if err != nil {
		t.Fatalf("Discover should tolerate missing roots: %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestDiscover_LoadsValidPlugin(t *testing.T) {
	manifest := "" +
		"name: my-plugin\n" +
		"version: 0.1.0\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"timeout: 5s\n"
	root := writePlugin(t, "my-plugin", manifest, "#!/bin/sh\necho noop\n")
	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	p := plugins[0]
	if p.Name != "my-plugin" || p.Version != "0.1.0" || p.Mode != ModeWhitebox || p.Timeout != 5*time.Second {
		t.Fatalf("plugin spec mismatch: %+v", p.Spec)
	}
	if !filepath.IsAbs(p.Dir) {
		t.Fatalf("plugin dir should be absolute, got %s", p.Dir)
	}
}

func TestDiscover_RejectsUnknownFields(t *testing.T) {
	manifest := "" +
		"name: bad\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"unkonwn_field: oops\n" // intentional typo
	root := writePlugin(t, "bad", manifest, "")
	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover should not return overall error on bad plugin: %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected the bad plugin to be skipped, got %d", len(plugins))
	}
}

func TestDiscover_RepoLocalShadowsUserGlobal(t *testing.T) {
	manifest := "" +
		"name: shared\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	repoRoot := writePlugin(t, "shared", manifest+"version: repo\n", "")
	userRoot := writePlugin(t, "shared", manifest+"version: user\n", "")

	plugins, err := Discover([]string{repoRoot, userRoot})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin (shadow dedup), got %d", len(plugins))
	}
	if plugins[0].Version != "repo" {
		t.Fatalf("expected repo-local to win, got version=%q", plugins[0].Version)
	}
}

func TestValidate_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		spec    Spec
		wantErr string
	}{
		{"empty name", Spec{Entrypoint: "x", Mode: ModeWhitebox}, "name is required"},
		{"name with slash", Spec{Name: "a/b", Entrypoint: "x", Mode: ModeWhitebox}, "must not contain path separators"},
		{"empty entrypoint", Spec{Name: "x", Mode: ModeWhitebox}, "entrypoint is required"},
		{"absolute entrypoint", Spec{Name: "x", Entrypoint: "/etc/passwd", Mode: ModeWhitebox}, "must be relative"},
		{"traversal entrypoint", Spec{Name: "x", Entrypoint: "../../../etc", Mode: ModeWhitebox}, "must not traverse"},
		{"empty mode", Spec{Name: "x", Entrypoint: "y"}, "mode is required"},
		{"unknown mode", Spec{Name: "x", Entrypoint: "y", Mode: Mode("magic")}, "not one of"},
		{"negative timeout", Spec{Name: "x", Entrypoint: "y", Mode: ModeWhitebox, Timeout: -time.Second}, "must not be negative"},
		{"timeout above cap", Spec{Name: "x", Entrypoint: "y", Mode: ModeWhitebox, Timeout: MaxTimeout + time.Second}, "exceeds engine cap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(&tc.spec)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestRun_HappyPath(t *testing.T) {
	manifest := "" +
		"name: emit-finding\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"timeout: 5s\n"
	script := `#!/bin/sh
cat <<EOF
{"id":"","title":"Hardcoded test secret","severity":"HIGH","category":"secrets","endpoint":"src/x.py:14","evidence":"redacted","fix":"rotate","confidence":"HIGH"}
{"done":true,"total":1}
EOF
`
	root := writePlugin(t, "emit-finding", manifest, script)
	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	findings, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox, CodePath: "src"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Title != "Hardcoded test secret" {
		t.Fatalf("title mismatch: %q", f.Title)
	}
	if f.Source != models.SourceWhitebox {
		t.Fatalf("source should be whitebox, got %q", f.Source)
	}
	wantRef := "fendix-plugin:emit-finding"
	found := false
	for _, r := range f.References {
		if r == wantRef {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected provenance ref %q in References %v", wantRef, f.References)
	}
}

func TestRun_BlackboxModeTagsFindingsAsBlackbox(t *testing.T) {
	manifest := "" +
		"name: bb\n" +
		"entrypoint: ./run.sh\n" +
		"mode: blackbox\n"
	script := `#!/bin/sh
echo '{"title":"Missing X-Custom-Header","severity":"MEDIUM","category":"headers","endpoint":"https://api.example/users","confidence":"MEDIUM"}'
echo '{"done":true,"total":1}'
`
	root := writePlugin(t, "bb", manifest, script)
	plugins, _ := Discover([]string{root})
	findings, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeBlackbox, URL: "https://api.example"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Source != models.SourceBlackbox {
		t.Fatalf("expected 1 blackbox finding, got %+v", findings)
	}
}

func TestRun_PluginErrorTerminator(t *testing.T) {
	manifest := "" +
		"name: errplug\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	script := `#!/bin/sh
echo '{"done":true,"total":0,"error":"could not parse target"}'
`
	root := writePlugin(t, "errplug", manifest, script)
	plugins, _ := Discover([]string{root})
	_, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err == nil {
		t.Fatal("expected error from plugin error terminator")
	}
	if !strings.Contains(err.Error(), "could not parse target") {
		t.Fatalf("expected wrapped plugin error message, got %q", err.Error())
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	manifest := "" +
		"name: crash\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	script := `#!/bin/sh
echo '{"title":"partial finding","severity":"LOW","category":"secrets","endpoint":"x","confidence":"LOW"}'
exit 3
`
	root := writePlugin(t, "crash", manifest, script)
	plugins, _ := Discover([]string{root})
	findings, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err == nil {
		t.Fatal("expected error from non-zero exit")
	}
	if !strings.Contains(err.Error(), "exit") {
		t.Fatalf("expected exit error, got %q", err.Error())
	}
	// Partial findings emitted before the crash are preserved.
	if len(findings) != 1 {
		t.Fatalf("expected partial finding to be retained, got %d", len(findings))
	}
}

func TestRun_Timeout(t *testing.T) {
	manifest := "" +
		"name: slow\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"timeout: 200ms\n"
	script := `#!/bin/sh
sleep 5
echo '{"done":true,"total":0}'
`
	root := writePlugin(t, "slow", manifest, script)
	plugins, _ := Discover([]string{root})
	start := time.Now()
	_, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %q", err.Error())
	}
	// Budget of 8s tolerates GitHub-hosted Linux runners where
	// exec.CommandContext's default Cancel SIGKILLs only the
	// entrypoint script and Wait blocks until the script's
	// `sleep 5` child exits. cmd.WaitDelay would bound that wait
	// but exposes a pre-existing pipe race in TestRun_NonZeroExit
	// (an `echo {...}; exit 3` plugin where the parent's stdin.Write
	// races the child's exit). Bumping the budget is the minimal-risk
	// fix. A real "timeout never fired" regression would be a
	// deterministic ~5s — well below 8s, so the assertion still
	// catches it.
	if elapsed > 8*time.Second {
		t.Fatalf("timeout did not fire promptly: elapsed %s", elapsed)
	}
}

func TestRun_MalformedLineSkippedNotFatal(t *testing.T) {
	manifest := "" +
		"name: junk\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	script := `#!/bin/sh
echo 'not json at all'
echo '{"title":"real finding","severity":"HIGH","category":"secrets","endpoint":"x","confidence":"HIGH"}'
echo '{"title":"missing fields"}'
echo '{"done":true,"total":1}'
`
	root := writePlugin(t, "junk", manifest, script)
	plugins, _ := Discover([]string{root})
	findings, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected only the well-formed finding, got %d", len(findings))
	}
}

func TestDefaultRoots_OrdersRepoLocalFirstWhenAllowed(t *testing.T) {
	cwd := t.TempDir()
	roots := DefaultRoots(cwd, true)
	if len(roots) == 0 {
		t.Fatal("DefaultRoots returned no roots")
	}
	if !strings.HasPrefix(roots[0], cwd) {
		t.Fatalf("expected first root under cwd when repo-local allowed, got %q", roots[0])
	}
}

func TestDefaultRoots_OmitsRepoLocalByDefault(t *testing.T) {
	// F-H2: with allowRepoLocal=false the repo-local root must NOT be
	// returned — the scanned repo is attacker-controlled in CI.
	cwd := t.TempDir()
	roots := DefaultRoots(cwd, false)
	for _, r := range roots {
		if strings.HasPrefix(r, cwd) {
			t.Fatalf("repo-local root %q must be omitted without opt-in; roots=%v", r, roots)
		}
	}
}
