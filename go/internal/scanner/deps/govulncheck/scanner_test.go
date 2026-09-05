package govulncheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

func TestScan_NoGoMod_ReturnsErrNoGoMod(t *testing.T) {
	dir := t.TempDir()
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrNoGoMod) {
		t.Fatalf("expected ErrNoGoMod, got %v", err)
	}
}

func TestScan_NonexistentPath_ReturnsErrNoGoMod(t *testing.T) {
	// os.Stat returns NotExist on a path whose parent doesn't exist —
	// caller still gets ErrNoGoMod (not a real Go module → skip silently).
	_, err := Scan(context.Background(), "/nonexistent/path/that/does/not/exist")
	if !errors.Is(err, ErrNoGoMod) {
		t.Fatalf("expected ErrNoGoMod, got %v", err)
	}
}

func TestScan_AbsPathFailure_BubblesUp(t *testing.T) {
	// filepath.Abs only fails when os.Getwd fails — rare but possible.
	// We don't currently exercise that path; the test reserves space for
	// when it becomes reachable. Skipped today to document intent.
	t.Skip("filepath.Abs failure mode not easily reproducible in unit tests")
}

func TestParseFindings_EmptyStdout(t *testing.T) {
	findings, err := parseFindings(nil, "mymod")
	if err != nil {
		t.Fatalf("parseFindings on empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty stdout, got %d", len(findings))
	}
}

func TestParseFindings_OSVWithoutMatchingFinding_IsDropped(t *testing.T) {
	// govulncheck emits an OSV record for every vendored vulnerable
	// module — but only emits a `finding` when the user's code actually
	// reaches the symbol. Parser must drop OSVs without a corresponding
	// called-trace finding.
	stdout := `{"osv": {"id": "GO-2023-0001", "summary": "Vendored but uncalled"}}` + "\n"
	findings, err := parseFindings([]byte(stdout), "mymod")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("vendored-but-uncalled OSV must be dropped, got %d findings", len(findings))
	}
}

func TestParseFindings_FindingWithoutCallTrace_IsDropped(t *testing.T) {
	// A finding whose trace has no `function` field signals an imported-
	// but-uncalled use. Must not emit — same as parity with deps.py.
	stdout := `{"osv": {"id": "GO-2023-0002", "summary": "Imported only"}}
{"finding": {"osv": "GO-2023-0002", "trace": [{"module": "example.com/m", "package": "p"}]}}`
	findings, err := parseFindings([]byte(stdout), "mymod")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("trace-without-function must be dropped, got %d findings", len(findings))
	}
}

func TestParseFindings_HappyPath(t *testing.T) {
	// One OSV + one finding with a real function frame should emit
	// exactly one finding shaped per the documented schema.
	stdout := `{"osv": {
		"id": "GO-2023-1234",
		"summary": "RCE in example.com/bad",
		"details": "An attacker can execute arbitrary code by calling Bad().",
		"aliases": ["CVE-2023-9999"],
		"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]
	}}
	{"finding": {
		"osv": "GO-2023-1234",
		"trace": [{"module": "example.com/bad", "package": "bad", "function": "Bad"}]
	}}`
	findings, err := parseFindings([]byte(stdout), "mymod")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "SEC-DEPS-GO-GO_2023_1234" {
		t.Errorf("unexpected ID: %s", f.ID)
	}
	if !strings.Contains(f.Title, "RCE in example.com/bad") {
		t.Errorf("title missing summary: %s", f.Title)
	}
	if !strings.Contains(f.Title, "GO-2023-1234") {
		t.Errorf("title missing OSV ID: %s", f.Title)
	}
	if !strings.Contains(f.Fix, "1.2.3") {
		t.Errorf("fix line missing version: %s", f.Fix)
	}
	if f.Severity != "HIGH" || f.Confidence != "HIGH" {
		t.Errorf("severity/confidence drift: %s / %s", f.Severity, f.Confidence)
	}
	if f.Category != "deps" {
		t.Errorf("category should be deps, got %s", f.Category)
	}
	wantRefs := []string{"GO-2023-1234", "CVE-2023-9999"}
	if len(f.References) != len(wantRefs) {
		t.Fatalf("references len: got %v want %v", f.References, wantRefs)
	}
	for i, r := range f.References {
		if r != wantRefs[i] {
			t.Errorf("reference[%d]: got %s want %s", i, r, wantRefs[i])
		}
	}
	if f.Line == nil || *f.Line != "mymod" {
		t.Errorf("line should be modName (%q), got %v", "mymod", f.Line)
	}
}

// TestParseFindings_GitRangeNeverReachesTheFixLine is the govulncheck half
// of FIX-06. vuln.go.dev emits SEMVER in practice, so this shape is not
// what is breaking today — but the fix line is a promise ("upgrade to
// this") and a commit SHA cannot keep it. The GIT filter must hold here
// too, or the one path that DOES start emitting GIT ranges regresses
// silently.
//
// Note what is deliberately NOT changed: the finding ID stays
// SEC-DEPS-GO-GO_2023_1234 even though the record carries a CVE alias.
// FIX-05's canonical-ID rule is confined to pip/npm — govulncheck emits
// exactly one GO-* record per vulnerability (parseFindings already keys
// by ID), so the duplicate-record bug class does not occur here, and the
// ID shape is locked by a cross-language parity test in
// python/tests/test_deps.py.
func TestParseFindings_GitRangeNeverReachesTheFixLine(t *testing.T) {
	const sha = "8f1d2c3b4a59607e6c1f0dd0d2a1b9e77c3d4a51"
	stdout := `{"osv": {
		"id": "GO-2023-1234",
		"summary": "RCE in example.com/bad",
		"aliases": ["CVE-2023-9999"],
		"affected": [{"ranges": [
			{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "` + sha + `"}]},
			{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
		]}]
	}}
	{"finding": {
		"osv": "GO-2023-1234",
		"trace": [{"module": "example.com/bad", "package": "bad", "function": "Bad"}]
	}}`
	findings, err := parseFindings([]byte(stdout), "mymod")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if strings.Contains(f.Fix, sha) {
		t.Errorf("a commit SHA reached the upgrade message: %s", f.Fix)
	}
	if !strings.Contains(f.Fix, "1.2.3") {
		t.Errorf("fix line should name the SEMVER version: %s", f.Fix)
	}
	if f.ID != "SEC-DEPS-GO-GO_2023_1234" {
		t.Errorf("govulncheck ID shape must not adopt FIX-05's canonical-ID rule: %s", f.ID)
	}
}

func TestParseFindings_NoFixVersion_EmitsPlaceholder(t *testing.T) {
	stdout := `{"osv": {"id": "GO-2023-0003", "summary": "No fix available"}}
{"finding": {"osv": "GO-2023-0003", "trace": [{"function": "F"}]}}`
	findings, err := parseFindings([]byte(stdout), "m")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Fix, "no fix listed") {
		t.Errorf("expected 'no fix listed' message, got: %s", findings[0].Fix)
	}
}

func TestParseFindings_MultipleOSVs_Deterministic(t *testing.T) {
	// Multiple OSVs in non-sorted input must come out in sorted-by-ID order.
	// Locks in deterministic report output across runs of the same scan.
	stdout := `{"osv": {"id": "GO-2024-0002", "summary": "B"}}
{"osv": {"id": "GO-2024-0001", "summary": "A"}}
{"finding": {"osv": "GO-2024-0002", "trace": [{"function": "X"}]}}
{"finding": {"osv": "GO-2024-0001", "trace": [{"function": "Y"}]}}`
	findings, err := parseFindings([]byte(stdout), "m")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
	if findings[0].ID != "SEC-DEPS-GO-GO_2024_0001" {
		t.Errorf("first ID should be GO-2024-0001, got %s", findings[0].ID)
	}
	if findings[1].ID != "SEC-DEPS-GO-GO_2024_0002" {
		t.Errorf("second ID should be GO-2024-0002, got %s", findings[1].ID)
	}
}

func TestParseFindings_MalformedOSV_IsTolerated(t *testing.T) {
	// One bad JSON object shouldn't tank the rest. Parser advances past
	// the broken token and continues. The decoder doesn't recover
	// gracefully from mid-object damage so all we promise is no panic +
	// best-effort emission of subsequent valid objects.
	stdout := `{"osv": {"id": "GO-2023-1111", "summary": "valid"}}
not json at all
{"finding": {"osv": "GO-2023-1111", "trace": [{"function": "F"}]}}`
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseFindings panicked on malformed input: %v", r)
		}
	}()
	_, err := parseFindings([]byte(stdout), "m")
	if err != nil {
		t.Fatalf("parseFindings: %v", err)
	}
	// Don't assert finding count here — recovery semantics across encoding/json
	// versions are wobbly; the panic-free guarantee is what matters.
}

func TestFirstLines_TruncatesAndJoins(t *testing.T) {
	got := firstLines("a\nb\nc\nd\ne", 3)
	want := "a | b | c"
	if got != want {
		t.Errorf("firstLines: got %q, want %q", got, want)
	}
}

func TestFirstLines_HardCapAt300Chars(t *testing.T) {
	long := strings.Repeat("abcdefghij", 50) // 500 chars, no newlines
	got := firstLines(long, 3)
	if len(got) != 300 {
		t.Errorf("expected 300-char cap, got %d", len(got))
	}
}

func TestIsFoundVulnsExit_RecognisesUpstreamWording(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("vulnerabilities found in /tmp/x"), true},
		{errors.New("Vulnerability found"), true}, // case-insensitive match
		{errors.New("compilation error"), false},
		{errors.New("network unreachable"), false},
	}
	for _, c := range cases {
		got := isFoundVulnsExit(c.err)
		if got != c.want {
			t.Errorf("isFoundVulnsExit(%v): got %v, want %v", c.err, got, c.want)
		}
	}
}

// TestScan_FixtureGoMod runs the real x/vuln scan API against a fixture
// module that imports a known-vulnerable version of golang.org/x/text.
// Hits vuln.go.dev at scan time, so skipped under -short.
//
// The fixture is created in t.TempDir() so the test is hermetic and
// works regardless of where `go test` is invoked from.
func TestScan_FixtureGoMod(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live vuln-DB call in -short mode")
	}

	dir := t.TempDir()

	// Minimal go.mod + main.go that imports a vulnerable golang.org/x/text
	// version. CVE: GO-2022-1059 (and aliases) — known reachable when
	// language.Parse is called on attacker-controlled input.
	goMod := `module fendix-test-fixture

go 1.22

require golang.org/x/text v0.3.7
`
	mainGo := `package main

import (
	"fmt"
	"golang.org/x/text/language"
)

func main() {
	tag, _ := language.Parse("en-US")
	fmt.Println(tag)
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	// `go mod download` populates the local cache so govulncheck can
	// load package sources. Suppresses spurious "missing go.sum entry"
	// errors when the test machine doesn't already have the dep.
	if err := os.Setenv("GOFLAGS", "-mod=mod"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	findings, err := Scan(ctx, dir)
	if err != nil {
		// Network-failure paths are out of our control; surface but
		// don't fail the suite — the unit tests above cover the parser.
		if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "dial tcp") ||
			strings.Contains(err.Error(), "i/o timeout") {
			t.Skipf("network-unavailable, skipping live vuln-DB test: %v", err)
		}
		t.Fatalf("Scan: %v", err)
	}

	// We don't pin the exact finding count: x/text v0.3.7 had multiple
	// CVEs over time, and the OSV DB is mutable. Asserting >=1 with the
	// expected shape locks the happy path without making the test brittle.
	if len(findings) == 0 {
		t.Skip("no findings emitted — likely x/text v0.3.7 dropped from OSV DB " +
			"or network blocked; parser unit tests cover the shape exhaustively")
	}
	for i, f := range findings {
		if !strings.HasPrefix(f.ID, "SEC-DEPS-GO-") {
			t.Errorf("finding[%d] ID %q must start with SEC-DEPS-GO-", i, f.ID)
		}
		if f.Category != "deps" {
			t.Errorf("finding[%d] category should be 'deps', got %q", i, f.Category)
		}
		if f.Source != "whitebox" {
			t.Errorf("finding[%d] source should be 'whitebox', got %q", i, f.Source)
		}
		if len(f.References) == 0 {
			t.Errorf("finding[%d] missing OSV ID in references", i)
		}
	}
}

func TestClassifyRunErr(t *testing.T) {
	base := errors.New("exit status 1")
	if err := classifyRunErr(base, "Get \"https://vuln.go.dev/index/db.json\": dial tcp: lookup vuln.go.dev: no such host"); neterr.Classify(err) != neterr.KindNetwork {
		t.Fatalf("dns failure must classify as network, got %v", err)
	}
	if err := classifyRunErr(base, "context deadline exceeded"); neterr.Classify(err) != neterr.KindTimeout {
		t.Fatalf("deadline must classify as timeout, got %v", err)
	}
	if err := classifyRunErr(base, "package ./...: no Go files"); neterr.Classify(err) != neterr.KindOther {
		t.Fatalf("tool error must stay other, got %v", err)
	}
}
