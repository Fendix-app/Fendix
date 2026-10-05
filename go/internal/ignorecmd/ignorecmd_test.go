package ignorecmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/engine"
)

// writeIgnore writes content to a temp .fendix-ignore and returns the path.
func writeIgnore(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".fendix-ignore")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// classifyRule — status / sort-rank assignment
// ---------------------------------------------------------------------------

func TestClassifyRule_NoExpiry(t *testing.T) {
	r := engine.IgnoreRule{ID: "SEC-001", Reason: "perm"}
	row := classifyRule(r, time.Now())
	if row.status != "no-expiry" {
		t.Errorf("status = %q; want no-expiry", row.status)
	}
	if row.statusRank != 3 {
		t.Errorf("rank = %d; want 3", row.statusRank)
	}
}

func TestClassifyRule_Expired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	r := engine.IgnoreRule{Endpoint: "/admin", Until: "2026-01-01"}
	row := classifyRule(r, now)
	if row.status != "EXPIRED" {
		t.Errorf("status = %q; want EXPIRED", row.status)
	}
	if row.statusRank != 0 {
		t.Errorf("rank = %d; want 0 (sorts first)", row.statusRank)
	}
}

func TestClassifyRule_ExpiringSoon(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// 20 days out, within the 30-day threshold
	r := engine.IgnoreRule{Endpoint: "/admin", Until: "2026-06-21"}
	row := classifyRule(r, now)
	if !strings.HasPrefix(row.status, "expiring-soon") {
		t.Errorf("status = %q; want expiring-soon prefix", row.status)
	}
	if row.statusRank != 1 {
		t.Errorf("rank = %d; want 1", row.statusRank)
	}
}

func TestClassifyRule_Active(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	r := engine.IgnoreRule{Category: "secrets", Until: "2027-01-01"}
	row := classifyRule(r, now)
	if row.status != "active" {
		t.Errorf("status = %q; want active", row.status)
	}
	if row.statusRank != 2 {
		t.Errorf("rank = %d; want 2", row.statusRank)
	}
}

func TestClassifyRule_InvalidDate(t *testing.T) {
	r := engine.IgnoreRule{Endpoint: "/x", Until: "not-a-date"}
	row := classifyRule(r, time.Now())
	if row.status != "INVALID-DATE" {
		t.Errorf("status = %q; want INVALID-DATE", row.status)
	}
}

func TestTargetSummary(t *testing.T) {
	cases := []struct {
		in   engine.IgnoreRule
		want string
	}{
		{engine.IgnoreRule{ID: "SEC-014"}, "id=SEC-014"},
		{engine.IgnoreRule{Endpoint: "/admin"}, "/admin"},
		{engine.IgnoreRule{Endpoint: "/x", Category: "auth"}, "/x [auth]"},
		{engine.IgnoreRule{Category: "secrets"}, "category=secrets"},
		{engine.IgnoreRule{}, "(empty rule)"},
	}
	for _, c := range cases {
		got := targetSummary(c.in)
		if got != c.want {
			t.Errorf("targetSummary(%+v) = %q; want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// runList
// ---------------------------------------------------------------------------

func TestRunList_NoFile(t *testing.T) {
	var out bytes.Buffer
	if err := runList(&out, "/nonexistent/.fendix-ignore"); err != nil {
		t.Fatalf("runList: %v", err)
	}
	if !strings.Contains(out.String(), "no .fendix-ignore") {
		t.Errorf("expected friendly missing-file message; got %q", out.String())
	}
}

func TestRunList_EmptyFile(t *testing.T) {
	path := writeIgnore(t, "ignore: []\n")
	var out bytes.Buffer
	if err := runList(&out, path); err != nil {
		t.Fatalf("runList: %v", err)
	}
	if !strings.Contains(out.String(), "no rules") {
		t.Errorf("expected 'no rules' message; got %q", out.String())
	}
}

func TestRunList_RenderRows(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-014
    reason: rate limit at gateway
  - endpoint: /admin
    category: auth
    until: 2099-12-01
    reason: known weak admin auth
`)
	var out bytes.Buffer
	if err := runList(&out, path); err != nil {
		t.Fatalf("runList: %v", err)
	}
	got := out.String()
	for _, want := range []string{"TARGET", "EXPIRES", "STATUS", "id=SEC-014", "/admin [auth]", "no-expiry", "active"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n%s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// runValidate
// ---------------------------------------------------------------------------

func TestRunValidate_Clean(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-001
  - endpoint: /admin
    until: 2099-01-01
`)
	var out bytes.Buffer
	errCount, err := runValidate(&out, path)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if errCount != 0 {
		t.Errorf("errCount = %d; want 0", errCount)
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("expected OK output; got %q", out.String())
	}
}

func TestRunValidate_InvalidDate(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - endpoint: /admin
    until: not-a-date
`)
	var out bytes.Buffer
	errCount, err := runValidate(&out, path)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if errCount != 1 {
		t.Errorf("errCount = %d; want 1", errCount)
	}
	if !strings.Contains(out.String(), "invalid until date") {
		t.Errorf("expected 'invalid until date' message; got %q", out.String())
	}
}

func TestRunValidate_EmptyRule(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - reason: I am alone
`)
	var out bytes.Buffer
	errCount, err := runValidate(&out, path)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if errCount != 1 {
		t.Errorf("errCount = %d; want 1", errCount)
	}
	if !strings.Contains(out.String(), "empty rule") {
		t.Errorf("expected 'empty rule' message; got %q", out.String())
	}
}

func TestRunValidate_MissingFileIsOK(t *testing.T) {
	var out bytes.Buffer
	errCount, err := runValidate(&out, "/nonexistent/.fendix-ignore")
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if errCount != 0 {
		t.Errorf("errCount = %d; want 0 for missing file", errCount)
	}
}

// ---------------------------------------------------------------------------
// runPrune
// ---------------------------------------------------------------------------

func TestRunPrune_DropsExpired(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-001
    until: 2020-01-01
  - id: SEC-002
    until: 2099-12-31
  - id: SEC-003
`)
	var out bytes.Buffer
	if err := runPrune(&out, path, false); err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if !strings.Contains(out.String(), "removed 1 expired") {
		t.Errorf("expected 'removed 1 expired'; got %q", out.String())
	}
	// Re-parse the file to confirm SEC-001 is gone, others kept.
	ig, err := engine.ParseIgnoreFile(path)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(ig.Ignore) != 2 {
		t.Fatalf("after prune got %d rules; want 2", len(ig.Ignore))
	}
	for _, r := range ig.Ignore {
		if r.ID == "SEC-001" {
			t.Errorf("SEC-001 not removed")
		}
	}
}

func TestRunPrune_DryRunDoesNotWrite(t *testing.T) {
	original := `ignore:
  - id: SEC-001
    until: 2020-01-01
`
	path := writeIgnore(t, original)
	var out bytes.Buffer
	if err := runPrune(&out, path, true); err != nil {
		t.Fatalf("runPrune dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("expected dry-run marker; got %q", out.String())
	}
	// File content should be unchanged
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != original {
		t.Errorf("file was rewritten under --dry-run\nbefore: %q\nafter:  %q", original, string(got))
	}
}

func TestRunPrune_NoExpiredRules(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-001
    until: 2099-12-31
`)
	var out bytes.Buffer
	if err := runPrune(&out, path, false); err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if !strings.Contains(out.String(), "no expired rules") {
		t.Errorf("expected 'no expired rules'; got %q", out.String())
	}
}

func TestRunPrune_PreservesInvalidDates(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-001
    until: not-a-date
  - id: SEC-002
    until: 2020-01-01
`)
	var out bytes.Buffer
	if err := runPrune(&out, path, false); err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	ig, _ := engine.ParseIgnoreFile(path)
	hasInvalid := false
	for _, r := range ig.Ignore {
		if r.ID == "SEC-001" {
			hasInvalid = true
		}
		if r.ID == "SEC-002" {
			t.Errorf("SEC-002 (expired) not dropped")
		}
	}
	if !hasInvalid {
		t.Errorf("rule with invalid date should be preserved (let `validate` surface it)")
	}
}
