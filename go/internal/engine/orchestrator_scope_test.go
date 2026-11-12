package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 through the orchestrator: secrets and textscan record an
// in-scope file they left unread as failed/execution_error naming it (the
// scan reads incomplete), keep the findings from the rest of the tree, and
// list declared generated artifacts and pruned directories in their ok
// detail. Semgrep's half is in scannerstatus_scope_test.go and, with the real
// binary, in the semgrep package.

func padPast(body string) string {
	var b strings.Builder
	b.WriteString(body)
	for b.Len() <= scope.MaxFileBytes {
		b.WriteString("// padding padding padding padding padding padding padding padding\n")
	}
	return b.String()
}

// padJSONLockfile is a package-lock.json over the size cap that parses as one.
func padJSONLockfile() string {
	return `{"lockfileVersion": 3, "packages": {"": {"name": "x"}}, "pad": "` + strings.Repeat("0123456789", scope.MaxFileBytes/10+10) + `"}` + "\n"
}

// padMinified is a bundle over the size cap: a few very long lines.
func padMinified() string {
	var b strings.Builder
	for b.Len() <= scope.MaxFileBytes+1024 {
		b.WriteString("!function(){" + strings.Repeat("a=b(c,d);", 3000) + "}();\n")
	}
	return b.String()
}

func runCodeScan(t *testing.T, root string) reporters.JSONReport {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath: root, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
		Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"),
		Fast: true, PythonEngine: false, NoPlugins: true,
	}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	return readReport(t, out)
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrchestrator_SizeSkippedInScopeFilesAreAGap(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"web/app.js": "el.innerHTML = location.hash;\n",
		"web/big.js": padPast("el.innerHTML = location.hash;\nconst k = \"AKIA" + "BIGFILESYNTHET01\";\n"),
	})
	report := runCodeScan(t, root)
	for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan} {
		s, ok := statusFor(report, name)
		// secrets streams a file far past the 1 MiB cap the other analyzers keep
		// (secrets4), so it reads web/big.js and is no gap for it; whichever way
		// an analyzer goes, it must not read ok having skipped the file.
		if name == AnalyzerSecrets && ok && s.State == reporters.ScannerOK {
			continue
		}
		if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonExecutionError {
			t.Errorf("%s = %+v; want failed/execution_error", name, s)
			continue
		}
		if !strings.Contains(s.Detail, "web/big.js") || !strings.Contains(s.Detail, "over 1048576 bytes") {
			t.Errorf("%s detail %q does not name web/big.js as over the cap", name, s.Detail)
		}
	}
	if report.Metadata.Coverage == nil || report.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("coverage = %+v; want incomplete", report.Metadata.Coverage)
	}
	found := false
	for _, f := range report.Findings {
		if strings.HasPrefix(f.Endpoint, "web/app.js") {
			found = true
		}
	}
	if !found {
		t.Errorf("the finding in web/app.js was not kept: %+v", report.Findings)
	}
}

func TestOrchestrator_DeclaredScopeStaysCompleteAndIsListed(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"web/app.js": "const x = 1;\n",
		// D6': the evidence is in the content. A lockfile that parses as one, a
		// bundle that is one long line, and an installed npm tree with its marker.
		"package-lock.json":               padJSONLockfile(),
		"public/app.min.js":               padMinified(),
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/x/i.js":             "const y = 2;\n",
	})
	report := runCodeScan(t, root)
	for _, tc := range []struct {
		name  string
		wants []string
	}{
		{AnalyzerSecrets, []string{"declared out of scope, not scanned", "node_modules/"}},
		{AnalyzerTextscan, []string{"declared out of scope, not scanned", "public/app.min.js", "node_modules/"}},
	} {
		s, ok := statusFor(report, tc.name)
		if !ok || s.State != reporters.ScannerOK {
			t.Errorf("%s = %+v; want ok", tc.name, s)
			continue
		}
		for _, w := range tc.wants {
			if !strings.Contains(s.Detail, w) {
				t.Errorf("%s detail %q lacks %q", tc.name, s.Detail, w)
			}
		}
	}
	for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan} {
		if report.Metadata.Coverage != nil && containsString(report.Metadata.Coverage.Gaps, name) {
			t.Errorf("%s is a gap: %+v", name, report.Metadata.Coverage)
		}
	}
}

// verify-secrets2's open question: a --code that is itself a symbolic link is
// resolved once, for every analyzer.
func TestOrchestrator_LinkedCodeRootIsScannedByEveryAnalyzer(t *testing.T) {
	real := t.TempDir()
	writeFiles(t, real, map[string]string{"web/app.js": "el.innerHTML = location.hash;\nconst k = \"AKIA" + "LINKEDROOTSYNT01\";\n"})
	link := filepath.Join(t.TempDir(), "code")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	report := runCodeScan(t, link)
	if len(report.Findings) == 0 {
		t.Fatal("no findings through the linked root")
	}
	for _, f := range report.Findings {
		if strings.HasPrefix(f.Endpoint, "/") || strings.Contains(f.Endpoint, "..") {
			t.Errorf("finding endpoint %q is not relative to the root", f.Endpoint)
		}
	}
	for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan} {
		if s, _ := statusFor(report, name); s.State != reporters.ScannerOK {
			t.Errorf("%s = %+v; want ok", name, s)
		}
	}
}
