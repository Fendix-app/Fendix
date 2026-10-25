//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Files added by the change under review. Each is caught by a native scanner
// that diff mode scopes: semgrep (the Flask route), textscan (the privileged
// container blocks at --fail-on HIGH; child_process warns) and secrets (the
// regression guard).
var relativeRootFixture = map[string]string{
	"app/server.py": "import subprocess\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n" +
		"@app.route(\"/run\")\ndef run():\n    cmd = request.args.get(\"cmd\", \"\")\n    return subprocess.check_output(cmd, shell=True)\n",
	"deploy/k8s/worker.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: worker\nspec:\n  containers:\n    - name: worker\n" +
		"      image: example/worker\n      securityContext:\n        privileged: true\n",
	"src/jobs.js":        "const child_process = require(\"child_process\");\nfunction run(name) { return child_process.exec(\"run \" + name); }\n",
	"config/settings.py": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
}

type ruleReport struct {
	Total    int `json:"total"`
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Endpoint string `json:"endpoint"`
		Status   string `json:"status"`
	} `json:"findings"`
}

// scanFromRepo runs `fendix scan` with the repository as the working
// directory, as the composite Action does, and returns the exit code and the
// findings as sorted "rule @ endpoint [status]" keys.
func scanFromRepo(t *testing.T, bin, repo string, args ...string) (int, []string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"scan", "--python-engine=false", "--fail-on", "HIGH", "--format", "json"}, args...)...)
	cmd.Dir = repo
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() > 1 {
			t.Fatalf("fendix scan %v: %v\n%s", args, err, exitStderr(err))
		}
		code = ee.ExitCode()
	}
	var rep ruleReport
	if jerr := json.Unmarshal(out, &rep); jerr != nil {
		t.Fatalf("fendix scan %v: report is not JSON: %v\n%s", args, jerr, out)
	}
	keys := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		keys = append(keys, f.RuleID+" @ "+f.Endpoint+" ["+f.Status+"]")
	}
	sort.Strings(keys)
	return code, keys
}

func hasRule(keys []string, rule string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, rule+" @ ") {
			return true
		}
	}
	return false
}

// TestDiffRefScan_RelativeCodeRootMatchesAbsolute_E2E is the composite
// Action's pull-request path: the working directory is the repository,
// `--code .` (the input default) and `--diff=<base>`. Through v3.6.1 the
// relative root made semgrep and textscan scan none of the changed files while
// reporting a clean run, so a privileged container passed the gate. Every
// spelling of the root, and a full scan of the same commit, must report the
// same findings and the same exit code.
func TestDiffRefScan_RelativeCodeRootMatchesAbsolute_E2E(t *testing.T) {
	bin := fendixBinary(t)
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitInit(t, repo)
	write(t, filepath.Join(repo, "README.md"), "base\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "base")
	for rel, body := range relativeRootFixture {
		write(t, filepath.Join(repo, filepath.FromSlash(rel)), body)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "change under review")

	fullCode, full := scanFromRepo(t, bin, repo, "--code", ".")
	for _, rule := range []string{"IAC_K8S_PRIVILEGED_CONTAINER", "JS_CHILD_PROCESS_SHELL"} {
		if !hasRule(full, rule) {
			t.Fatalf("full scan did not report %s; the fixture no longer exercises textscan: %v", rule, full)
		}
	}
	if _, lookErr := exec.LookPath("semgrep"); lookErr == nil {
		if !hasRule(full, "flask-route-no-auth-decorator") {
			t.Fatalf("semgrep is installed but the full scan reported no Flask route finding: %v", full)
		}
	} else {
		t.Log("semgrep not on PATH: this run checks textscan and secrets only; CI's e2e job installs semgrep")
	}
	if fullCode != 1 {
		t.Fatalf("full scan exit %d, want 1 (the privileged container blocks at --fail-on HIGH)", fullCode)
	}

	for _, code := range []string{".", "./", repo} {
		gotCode, got := scanFromRepo(t, bin, repo, "--code", code, "--diff=HEAD~1")
		if !reflect.DeepEqual(got, full) {
			t.Errorf("--code %q --diff=HEAD~1 reported\n  %v\nwant the full scan's\n  %v", code, got, full)
		}
		if gotCode != fullCode {
			t.Errorf("--code %q --diff=HEAD~1 exit %d, want %d", code, gotCode, fullCode)
		}
	}

	// The pre-commit hook `fendix hook install` writes runs exactly
	// `fendix scan --code . --staged --fast` from the repository root.
	write(t, filepath.Join(repo, "deploy/k8s/staged.yaml"), relativeRootFixture["deploy/k8s/worker.yaml"])
	git(t, repo, "add", "deploy/k8s/staged.yaml")
	var stagedWant []string
	for _, code := range []string{repo, ".", "./"} {
		gotCode, got := scanFromRepo(t, bin, repo, "--code", code, "--staged", "--fast")
		if code == repo {
			stagedWant = got
			if !hasRule(got, "IAC_K8S_PRIVILEGED_CONTAINER") || gotCode != 1 {
				t.Fatalf("staged scan with an absolute root: exit %d, findings %v; want the staged privileged container to block", gotCode, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, stagedWant) || gotCode != 1 {
			t.Errorf("hook command (--code %q --staged --fast): exit %d, findings %v; want exit 1 and %v", code, gotCode, got, stagedWant)
		}
	}
	git(t, repo, "commit", "-qm", "staged change")

	// No changed files: still scoped to nothing, whatever the spelling.
	for _, code := range []string{".", "./", repo} {
		gotCode, got := scanFromRepo(t, bin, repo, "--code", code, "--diff=HEAD")
		if len(got) != 0 || gotCode != 0 {
			t.Errorf("--code %q --diff=HEAD with no changes: exit %d, findings %v; want exit 0 and none", code, gotCode, got)
		}
	}
}

// scanWithStderr is scanFromRepo that also returns what the scan logged.
func scanWithStderr(t *testing.T, bin, repo string, args ...string) (int, []string, string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"scan", "--python-engine=false", "--fail-on", "HIGH", "--format", "json"}, args...)...)
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() > 1 {
			t.Fatalf("fendix scan %v: %v\n%s", args, err, stderr.String())
		}
		code = ee.ExitCode()
	}
	var rep ruleReport
	if jerr := json.Unmarshal(stdout.Bytes(), &rep); jerr != nil {
		t.Fatalf("fendix scan %v: report is not JSON: %v\n%s", args, jerr, stdout.String())
	}
	keys := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		keys = append(keys, f.RuleID+" @ "+f.Endpoint+" ["+f.Status+"]")
	}
	sort.Strings(keys)
	return code, keys, stderr.String()
}

// TestDiffRefScan_SubdirectoryCodeRootFallsBackToFullScan_E2E proves only the
// v3.6.2 safety property for a --code below the repository root: git reports
// changed paths from the repository root, which the diff mapper cannot place
// under the subdirectory, so a non-empty diff must widen to a full scan of
// --code, with a warning, instead of scanning no file. Diff scoping for
// subdirectories is planned for a later release.
func TestDiffRefScan_SubdirectoryCodeRootFallsBackToFullScan_E2E(t *testing.T) {
	bin := fendixBinary(t)
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitInit(t, repo)
	write(t, filepath.Join(repo, "services/api/README.md"), "api\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "base")
	write(t, filepath.Join(repo, "services/api/deploy/worker.yaml"), relativeRootFixture["deploy/k8s/worker.yaml"])
	write(t, filepath.Join(repo, "web/app.js"), relativeRootFixture["src/jobs.js"])
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "change under review")

	wantCode, want := scanFromRepo(t, bin, repo, "--code", "services/api")
	if wantCode != 1 || !hasRule(want, "IAC_K8S_PRIVILEGED_CONTAINER") {
		t.Fatalf("full scan of services/api: exit %d, findings %v; want the privileged container to block", wantCode, want)
	}
	for _, code := range []string{"services/api", "./services/api", filepath.Join(repo, "services", "api")} {
		gotCode, got, logs := scanWithStderr(t, bin, repo, "--code", code, "--diff=HEAD~1")
		if gotCode != wantCode || !reflect.DeepEqual(got, want) {
			t.Errorf("--code %q --diff=HEAD~1: exit %d, findings %v; want the full scan's exit %d and %v", code, gotCode, got, wantCode, want)
		}
		if !strings.Contains(logs, "falling back to full scan") {
			t.Errorf("--code %q --diff=HEAD~1 did not warn that it fell back to a full scan; log:\n%s", code, logs)
		}
	}
}

// TestPreCommitHook_BlocksStagedPrivilegedManifest_E2E installs the hook the
// way a developer does (`fendix hook install`) and commits a staged
// privileged Kubernetes manifest. The hook runs
// `fendix scan --code . --staged --fast`; through v3.6.1 that relative root
// scoped textscan to no file and the commit went through.
func TestPreCommitHook_BlocksStagedPrivilegedManifest_E2E(t *testing.T) {
	bin := fendixBinary(t)
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitInit(t, repo)
	write(t, filepath.Join(repo, "README.md"), "base\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "base")

	install := exec.Command(bin, "hook", "install")
	install.Dir = repo
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("fendix hook install: %v\n%s", err, out)
	}

	write(t, filepath.Join(repo, "deploy/k8s/worker.yaml"), relativeRootFixture["deploy/k8s/worker.yaml"])
	git(t, repo, "add", "deploy/k8s/worker.yaml")

	// A PATH without any other fendix, so the hook falls back to the binary
	// that installed it, the build under test.
	commit := exec.Command(gitBin, "commit", "-qm", "add a privileged worker")
	commit.Dir = repo
	commit.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	out, err := commit.CombinedOutput()
	if err == nil {
		t.Fatalf("the pre-commit hook let a staged privileged container through:\n%s", out)
	}
	if !strings.Contains(string(out), "IAC_K8S_PRIVILEGED_CONTAINER") && !strings.Contains(string(out), "rivileged") {
		t.Errorf("the hook failed, but not on the privileged container:\n%s", out)
	}

	// The relative-root hook command agrees with its absolute-root equivalent.
	absCode, absKeys := scanFromRepo(t, bin, repo, "--code", repo, "--staged", "--fast")
	relCode, relKeys := scanFromRepo(t, bin, repo, "--code", ".", "--staged", "--fast")
	if absCode != 1 || relCode != absCode || !reflect.DeepEqual(relKeys, absKeys) {
		t.Errorf("hook command: --code . gave exit %d %v; absolute root gave exit %d %v", relCode, relKeys, absCode, absKeys)
	}
}
