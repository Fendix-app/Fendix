package verifycmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// semgrepPackSource maps a bundled JS/TS, Java or Go rule id to the source
// file a finding of that rule is anchored at.
func semgrepPackSource(ruleID string) (string, bool) {
	switch {
	case strings.HasPrefix(ruleID, "js-"):
		return "src/handlers/user.ts", true
	case strings.HasPrefix(ruleID, "java-"):
		return "src/main/java/app/UserController.java", true
	case strings.HasPrefix(ruleID, "go-"):
		return "internal/api/user.go", true
	}
	return "", false
}

// TestVerify_KeepsSemgrepPackFindings: `fendix verify` must keep a finding of
// every JS/TS, Java and Go Semgrep rule (the -taint and -sink ids) instead of
// refusing it as an unknown shape. A taint rule's finding is the shim tier
// while its language's gate is closed (R-pf86) and the taint tier once it
// opens; verify handles both the same way.
func TestVerify_KeepsSemgrepPackFindings(t *testing.T) {
	rules, err := semgrep.CatalogRules()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, r := range rules {
		rel, ok := semgrepPackSource(r.ID)
		if !ok {
			continue
		}
		for _, tier := range []models.SourceTier{models.TierSemgrepShim, models.TierSemgrepTaint} {
			t.Run(r.ID+"/"+string(tier), func(t *testing.T) {
				dir := t.TempDir()
				abs := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(abs, []byte("// source\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				baseline := writeBaseline(t, dir, []models.Finding{{
					ID:         "SEC-PACK-1",
					Title:      r.Title,
					Source:     models.SourceWhitebox,
					SourceTier: tier,
					Category:   r.Category,
					Endpoint:   rel + ":12",
					RuleID:     r.ID,
					Reachable:  tier == models.TierSemgrepTaint,
				}})
				res, err := Run(context.Background(), "SEC-PACK-1", Options{BaselinePath: baseline, CodePath: dir})
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				assertKeptSemgrepFinding(t, res, r.ID)
			})
		}
		checked++
	}
	if checked < 40 {
		t.Fatalf("only %d JS/Java/Go rules found in the catalog; the pack moved?", checked)
	}
}

// TestVerify_KeepsSemgrepFindingInModuleFiles: a Semgrep-anchored finding in
// an .mjs/.cjs/.mts/.cts file is a file finding too, not an unknown shape.
func TestVerify_KeepsSemgrepFindingInModuleFiles(t *testing.T) {
	for _, ext := range []string{".mjs", ".cjs", ".mts", ".cts"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			rel := "server/db" + ext
			if err := os.MkdirAll(filepath.Join(dir, "server"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, rel), []byte("// source\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			baseline := writeBaseline(t, dir, []models.Finding{{
				ID:         "SEC-JS-1",
				Source:     models.SourceWhitebox,
				SourceTier: models.TierSemgrepTaint,
				Category:   "injection",
				Endpoint:   rel + ":7",
				RuleID:     "js-sqli-taint",
				Reachable:  true,
			}})
			res, err := Run(context.Background(), "SEC-JS-1", Options{BaselinePath: baseline, CodePath: dir})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			assertKeptSemgrepFinding(t, res, "js-sqli-taint")
		})
	}
}

// A Semgrep finding whose source file is gone is still never "resolved": a
// missing file is not proof of remediation.
func TestVerify_SemgrepFindingWithMissingSourceIsNotResolved(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID: "SEC-GO-1", Source: models.SourceWhitebox, SourceTier: models.TierSemgrepTaint,
		Category: "injection", Endpoint: "internal/api/gone.go:3", RuleID: "go-sqli-taint", Reachable: true,
	}})
	res, err := Run(context.Background(), "SEC-GO-1", Options{BaselinePath: baseline, CodePath: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == StatusResolved || res.Status == StatusNotFound {
		t.Fatalf("status = %s, want a kept (unknown or still-present) verdict: %s", res.Status, res.Reason)
	}
}

func assertKeptSemgrepFinding(t *testing.T, res *Result, ruleID string) {
	t.Helper()
	if res.Status != StatusUnknown {
		t.Fatalf("status = %s, want %s (kept, not re-testable): %s", res.Status, StatusUnknown, res.Reason)
	}
	if strings.Contains(res.Reason, "does not yet support") {
		t.Errorf("finding refused as an unknown shape: %s", res.Reason)
	}
	for _, want := range []string{ruleID, "Semgrep", "fendix scan"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("reason %q should mention %q", res.Reason, want)
		}
	}
	if res.Original == nil {
		t.Errorf("original finding dropped from the result")
	}
}
