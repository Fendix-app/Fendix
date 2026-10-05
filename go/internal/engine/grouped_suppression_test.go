package engine

// Regression suite for "baselines and ignore rules suppress whole grouped
// findings" (v3.5.0 reproduction). Every test here pins one of the security
// invariants:
//
//  1. A newly introduced occurrence cannot inherit baseline suppression merely
//     because it groups with an old occurrence.
//  2. A path-scoped ignore cannot suppress an occurrence whose path does not
//     match the rule.
//  3. Directory lexical ordering cannot decide whether CI passes.
//  4. Presentation grouping cannot change security identity.
//  6. Partial suppression cannot leave a finding whose endpoint/evidence refer
//     to a suppressed occurrence while its verdict comes from a surviving one.
//
// (Invariant 5, lifecycle dispositions, lives in the backend.)

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

const (
	fixtureCredential = "def make_user(client):\n    return client.create(email=\"t@example.com\", password=\"Fixture-Pass-123\")\n"
	prodCredential    = "def connect(db):\n    return db.login(user=\"svc\", password=\"Pr0d-31337-Secret!\")\n"
)

// repoFiles writes files (relative path -> content) into a fresh repo root.
func repoFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type scanOpts struct {
	baseline, saveBaseline, ignore string
}

// codeScan runs the real orchestrator (native analyzers only, CLI defaults)
// over root with --fail-on HIGH and returns the exit code and JSON report.
func codeScan(t *testing.T, root string, o scanOpts) (int, reporters.JSONReport) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath: root, FailOn: "HIGH", Format: "json", OutputPath: out,
		EnforceConfidence: true, DeescalateTests: true,
		BaselinePath: o.baseline, SaveBaselinePath: o.saveBaseline, IgnorePath: o.ignore,
	}
	code := NewOrchestrator(cfg, "test").Run(context.Background())
	var rep reporters.JSONReport
	if code != 2 {
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatalf("parsing report: %v", err)
		}
	}
	return code, rep
}

func writeIgnore(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".fendix-ignore")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func occurrenceEndpoints(f models.Finding) []string {
	var out []string
	for _, o := range f.Occurrences {
		out = append(out, o.Endpoint)
	}
	return out
}

// passwordFindings returns the HARDCODED_PASSWORD findings of a report.
func passwordFindings(rep reporters.JSONReport) []models.Finding {
	var out []models.Finding
	for _, f := range rep.Findings {
		if f.RuleID == "secrets/HARDCODED_PASSWORD" {
			out = append(out, f)
		}
	}
	return out
}

// assertOnlyProduction checks that the report presents exactly one password
// finding, built entirely from the production occurrence, and that it blocks.
func assertOnlyProduction(t *testing.T, code int, rep reporters.JSONReport, prodFile string) {
	t.Helper()
	if code != 1 {
		t.Errorf("exit = %d, want 1 (a new HIGH production credential must block)", code)
	}
	pw := passwordFindings(rep)
	if len(pw) != 1 {
		t.Fatalf("want 1 password finding, got %d: %+v", len(pw), pw)
	}
	f := pw[0]
	wantEP := prodFile + ":2"
	if f.Endpoint != wantEP {
		t.Errorf("endpoint = %q, want %q", f.Endpoint, wantEP)
	}
	if f.Status != "BLOCK" {
		t.Errorf("status = %q, want BLOCK", f.Status)
	}
	if got := occurrenceEndpoints(f); !reflect.DeepEqual(got, []string{wantEP}) {
		t.Errorf("occurrences = %v, want only %s", got, wantEP)
	}
	if len(f.AffectedEndpoints) != 0 {
		t.Errorf("affected_endpoints = %v, want none (one surviving occurrence)", f.AffectedEndpoints)
	}
	// Invariant 6: nothing displayed may come from the suppressed fixture.
	if f.Secret == nil || f.Secret.File != prodFile {
		t.Errorf("secret metadata = %+v, want file %s", f.Secret, prodFile)
	}
	if f.Line == nil || *f.Line != wantEP {
		t.Errorf("line = %v, want %s", f.Line, wantEP)
	}
	if strings.Contains(f.Evidence, "t@example.com") || strings.Contains(f.Evidence, "Fixture") {
		t.Errorf("evidence still shows the suppressed fixture: %q", f.Evidence)
	}
	if strings.Contains(f.DecisionReason, "tests/") {
		t.Errorf("decision reason refers to the suppressed fixture: %q", f.DecisionReason)
	}
	if f.Fingerprint != f.Occurrences[0].Fingerprint {
		t.Errorf("fingerprint %s is not the surviving occurrence's %s", f.Fingerprint, f.Occurrences[0].Fingerprint)
	}
}

// Matrix 1, 2, 9: a tests-only baseline, then a production credential added
// under directories that sort before AND after "tests". The verdict must be
// identical for every name.
func TestBaseline_NewProductionCredentialBlocksRegardlessOfPathOrder(t *testing.T) {
	for _, dir := range []string{"aaa", "app", "tests0", "zapp", "zzz"} {
		t.Run(dir, func(t *testing.T) {
			root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential})
			base := filepath.Join(t.TempDir(), "base.json")
			code, rep := codeScan(t, root, scanOpts{saveBaseline: base})
			if code != 0 || len(passwordFindings(rep)) != 1 {
				t.Fatalf("tests-only scan: exit %d, %d password findings; want exit 0 and 1 (WARN)", code, len(passwordFindings(rep)))
			}

			prodFile := "pkg/" + dir + "/db.py"
			if err := os.MkdirAll(filepath.Join(root, "pkg", dir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(prodFile)), []byte(prodCredential), 0o644); err != nil {
				t.Fatal(err)
			}

			code, rep = codeScan(t, root, scanOpts{})
			if code != 1 {
				t.Fatalf("no baseline: exit = %d, want 1", code)
			}

			// Matrix 2: only the new occurrence is new; the baselined fixture
			// does not reappear because the group's representative changed.
			code, rep = codeScan(t, root, scanOpts{baseline: base})
			assertOnlyProduction(t, code, rep, prodFile)
		})
	}
}

// Matrix 3, 9: a test-path ignore rule must not suppress the production
// occurrence that groups with the fixture, in either sort order.
func TestIgnore_TestPathRuleDoesNotSuppressProductionOccurrence(t *testing.T) {
	ign := "ignore:\n  - endpoint: \"**/tests/**\"\n    reason: \"test fixtures\"\n"
	for _, dir := range []string{"app", "zapp"} {
		t.Run(dir, func(t *testing.T) {
			prodFile := "pkg/" + dir + "/db.py"
			root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, prodFile: prodCredential})
			code, rep := codeScan(t, root, scanOpts{ignore: writeIgnore(t, ign)})
			assertOnlyProduction(t, code, rep, prodFile)
		})
	}
}

// Matrix 4 and 15: the same rule suppresses the fixture when it is alone,
// including a top-level tests/ directory.
func TestIgnore_TestPathRuleSuppressesFixturesAlone(t *testing.T) {
	ign := "ignore:\n  - endpoint: \"**/tests/**\"\n    reason: \"test fixtures\"\n"
	for _, path := range []string{"tests/helpers.py", "pkg/tests/helpers.py", "a/b/c/tests/deep/helpers.py"} {
		t.Run(path, func(t *testing.T) {
			root := repoFiles(t, map[string]string{path: fixtureCredential})
			code, rep := codeScan(t, root, scanOpts{ignore: writeIgnore(t, ign)})
			if code != 0 || len(passwordFindings(rep)) != 0 {
				t.Errorf("exit %d, %d password findings; want the fixture suppressed", code, len(passwordFindings(rep)))
			}
		})
	}
}

// Matrix 5, 6, 7: a baseline with several known locations.
func TestBaseline_MultipleKnownLocations(t *testing.T) {
	files := map[string]string{
		"svc/a/tests/helpers.py": fixtureCredential,
		"svc/b/tests/helpers.py": fixtureCredential,
		"svc/c/tests/helpers.py": fixtureCredential,
	}
	root := repoFiles(t, files)
	base := filepath.Join(t.TempDir(), "base.json")
	if code, rep := codeScan(t, root, scanOpts{saveBaseline: base}); code != 0 || len(passwordFindings(rep)) != 1 || len(passwordFindings(rep)[0].Occurrences) != 3 {
		t.Fatalf("baseline scan: exit %d, findings %+v", code, passwordFindings(rep))
	}

	// 5: all known locations stay known.
	if code, rep := codeScan(t, root, scanOpts{baseline: base}); code != 0 || len(passwordFindings(rep)) != 0 {
		t.Fatalf("unchanged repo: exit %d, %d new findings; want 0", code, len(passwordFindings(rep)))
	}

	// 6: one new production location — only it is new.
	if err := os.MkdirAll(filepath.Join(root, "svc/m"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "svc/m/db.py"), []byte(prodCredential), 0o644); err != nil {
		t.Fatal(err)
	}
	code, rep := codeScan(t, root, scanOpts{baseline: base})
	assertOnlyProduction(t, code, rep, "svc/m/db.py")

	// 7: removing a baselined location creates nothing new.
	if err := os.Remove(filepath.Join(root, "svc/m/db.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "svc/b/tests/helpers.py")); err != nil {
		t.Fatal(err)
	}
	if code, rep := codeScan(t, root, scanOpts{baseline: base}); code != 0 || len(passwordFindings(rep)) != 0 {
		t.Fatalf("after removing a known location: exit %d, %d new findings; want 0", code, len(passwordFindings(rep)))
	}
}

// Matrix 14: a baseline written by an engine that predates occurrences (a
// bare array of grouped findings) must keep working without preserving the
// hole.
func TestBaseline_LegacyFormatCompatibility(t *testing.T) {
	const fixtureEP, prodEP = "pkg/tests/helpers.py:2", "pkg/zapp/db.py:2"
	root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, "pkg/zapp/db.py": prodCredential})
	_, full := codeScan(t, root, scanOpts{})
	pw := passwordFindings(full)
	if len(pw) != 1 || len(pw[0].Occurrences) != 2 {
		t.Fatalf("setup: want one grouped finding with 2 occurrences, got %+v", pw)
	}
	fixtureOcc := pw[0].Occurrences[0]
	if fixtureOcc.Endpoint != fixtureEP {
		t.Fatalf("setup: first occurrence %q", fixtureOcc.Endpoint)
	}

	// legacy writes what a pre-occurrence engine saved: grouped findings, no
	// occurrences, primary fields from the fixture.
	legacy := func(t *testing.T, affected []string, mutate func(*models.Finding)) string {
		t.Helper()
		f := pw[0]
		f.Endpoint, f.Occurrences, f.AffectedEndpoints = fixtureEP, nil, affected
		line := fixtureEP
		f.Line = &line
		f.Secret = &models.SecretRef{Identifier: "email", File: "pkg/tests/helpers.py"} // pre-fix identifier
		f.Evidence = "il=\"t@example.com\", password=\"[REDACTED]\")"
		if mutate != nil {
			mutate(&f)
		}
		f.Fingerprint = models.Fingerprint(f)
		data, err := json.MarshalIndent([]models.Finding{f}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "legacy.json")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("tests-only legacy baseline: production occurrence is new", func(t *testing.T) {
		code, rep := codeScan(t, root, scanOpts{baseline: legacy(t, nil, nil)})
		assertOnlyProduction(t, code, rep, "pkg/zapp/db.py")
	})

	t.Run("legacy baseline that recorded both locations: both known", func(t *testing.T) {
		code, rep := codeScan(t, root, scanOpts{baseline: legacy(t, []string{fixtureEP, prodEP}, nil)})
		if code != 0 || len(passwordFindings(rep)) != 0 {
			t.Errorf("exit %d, %d findings; a location the legacy baseline recorded is proven present", code, len(passwordFindings(rep)))
		}
	})

	t.Run("legacy location proof is exact: a different line is not proof", func(t *testing.T) {
		code, rep := codeScan(t, root, scanOpts{baseline: legacy(t, []string{fixtureEP, "pkg/zapp/db.py:9"}, nil)})
		assertOnlyProduction(t, code, rep, "pkg/zapp/db.py")
	})

	t.Run("legacy location proof needs the same kind of finding", func(t *testing.T) {
		code, rep := codeScan(t, root, scanOpts{baseline: legacy(t, []string{fixtureEP, prodEP}, func(f *models.Finding) {
			f.Title, f.RuleID = "Some other finding", "secrets/OTHER"
		})})
		if code != 1 || len(passwordFindings(rep)) != 1 {
			t.Errorf("exit %d, findings %+v; a location recorded for a different rule proves nothing", code, passwordFindings(rep))
		}
	})

	t.Run("a JSON report from this build is read occurrence-exactly", func(t *testing.T) {
		data, _ := json.Marshal(full)
		p := filepath.Join(t.TempDir(), "report.json")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if code, rep := codeScan(t, root, scanOpts{baseline: p}); code != 0 || len(passwordFindings(rep)) != 0 {
			t.Errorf("exit %d, %d findings; want everything known", code, len(passwordFindings(rep)))
		}
	})

	t.Run("an unsupported baseline_version fails closed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "future.json")
		if err := os.WriteFile(p, []byte(`{"baseline_version": 3, "findings": []}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _ := codeScan(t, root, scanOpts{baseline: p}); code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("a different fingerprint algorithm fails closed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "alg.json")
		if err := os.WriteFile(p, []byte(`{"baseline_version": 2, "fingerprint_algorithm": "fendix/v9", "findings": []}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _ := codeScan(t, root, scanOpts{baseline: p}); code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})
}

// Matrix 14 (save/load): --save-baseline writes format v2 with every
// occurrence, and the file round-trips through --baseline.
func TestBaseline_SaveWritesEveryOccurrence(t *testing.T) {
	root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, "pkg/zapp/db.py": prodCredential})
	base := filepath.Join(t.TempDir(), "base.json")
	codeScan(t, root, scanOpts{saveBaseline: base})
	data, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	var doc reporters.BaselineDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BaselineVersion != 2 || doc.FingerprintAlgorithm != models.FingerprintAlgorithm {
		t.Errorf("header = %d %q", doc.BaselineVersion, doc.FingerprintAlgorithm)
	}
	var eps []string
	for _, f := range doc.Findings {
		if f.RuleID == "secrets/HARDCODED_PASSWORD" {
			eps = occurrenceEndpoints(f)
		}
	}
	if !reflect.DeepEqual(eps, []string{"pkg/tests/helpers.py:2", "pkg/zapp/db.py:2"}) {
		t.Errorf("saved occurrences = %v", eps)
	}
	if code, rep := codeScan(t, root, scanOpts{baseline: base}); code != 0 || len(rep.Findings) != 0 {
		t.Errorf("round trip: exit %d, %d findings; want 0", code, len(rep.Findings))
	}
}

// Ignore selectors are occurrence-scoped (fingerprint) or group-scoped by
// documented design (id), and positional IDs survive partial suppression.
func TestIgnore_SelectorScopes(t *testing.T) {
	root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, "pkg/zapp/db.py": prodCredential})
	_, full := codeScan(t, root, scanOpts{})
	pw := passwordFindings(full)
	if len(pw) != 1 || len(pw[0].Occurrences) != 2 {
		t.Fatalf("setup: %+v", pw)
	}
	group := pw[0]

	t.Run("fingerprint suppresses only that occurrence", func(t *testing.T) {
		ign := fmt.Sprintf("ignore:\n  - fingerprint: %q\n", group.Occurrences[0].Fingerprint)
		code, rep := codeScan(t, root, scanOpts{ignore: writeIgnore(t, ign)})
		assertOnlyProduction(t, code, rep, "pkg/zapp/db.py")
		if got := passwordFindings(rep)[0].ID; got != group.ID {
			t.Errorf("positional ID changed under partial suppression: %s -> %s", group.ID, got)
		}
	})

	t.Run("the group's fingerprint is its primary occurrence's", func(t *testing.T) {
		if group.Fingerprint != group.Occurrences[0].Fingerprint {
			t.Errorf("group fingerprint %s is not an occurrence fingerprint", group.Fingerprint)
		}
	})

	t.Run("endpoint + category narrows to the occurrence", func(t *testing.T) {
		ign := "ignore:\n  - endpoint: \"pkg/tests/**\"\n    category: secrets\n"
		code, rep := codeScan(t, root, scanOpts{ignore: writeIgnore(t, ign)})
		assertOnlyProduction(t, code, rep, "pkg/zapp/db.py")
	})

	t.Run("id is group-scoped (documented)", func(t *testing.T) {
		ign := fmt.Sprintf("ignore:\n  - id: %q\n", group.ID)
		_, rep := codeScan(t, root, scanOpts{ignore: writeIgnore(t, ign)})
		if len(passwordFindings(rep)) != 0 {
			t.Errorf("an id rule names the whole presented group; got %+v", passwordFindings(rep))
		}
	})
}

// --- finalize-level tests: ordering, non-secret detectors -------------------

// finalizeOnce runs the orchestrator's finalization over hand-built evidence.
func finalizeOnce(t *testing.T, evs []evidence.Evidence, o scanOpts) ([]models.Finding, int) {
	t.Helper()
	cfg := &models.ScanConfig{
		FailOn: "HIGH", Format: "json", OutputPath: filepath.Join(t.TempDir(), "r.json"),
		EnforceConfidence: true, DeescalateTests: true,
		BaselinePath: o.baseline, SaveBaselinePath: o.saveBaseline, IgnorePath: o.ignore,
	}
	orch := NewOrchestrator(cfg, "test")
	in := make([]evidence.Evidence, len(evs))
	copy(in, evs)
	findings, decisions, ec := orch.finalize(in, reporters.ScanMetadata{StartedAt: time.Unix(0, 0), Version: "test", Mode: "whitebox"})
	if ec != 0 {
		t.Fatalf("finalize exit %d", ec)
	}
	code := 0
	for _, d := range decisions {
		if d.Status == "BLOCK" {
			code = 1
		}
	}
	return findings, code
}

func gsSecretEvidence(file, ident string) evidence.Evidence {
	ep := file + ":2"
	line := ep
	return evidence.Evidence{
		ID: "SEC-HARDCODED_PASSWORD", RuleID: "secrets/HARDCODED_PASSWORD", Title: "Hardcoded password",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets",
		Endpoint: ep, Line: &line, Evidence: "password=\"[REDACTED len=16]\"", Confidence: models.ConfidenceHigh,
		Secret: &models.SecretRef{Identifier: ident, File: file},
	}
}

func gsHeaderEvidence(path string) evidence.Evidence {
	return evidence.Evidence{
		ID: "SEC-CSP", RuleID: "headers/MISSING_CSP", Title: "Missing Content-Security-Policy header",
		Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers",
		Endpoint: "GET " + path, Evidence: "no CSP header", Confidence: models.ConfidenceHigh,
	}
}

func gsCodeEvidence(file string, line int) evidence.Evidence {
	ep := fmt.Sprintf("%s:%d", file, line)
	l := ep
	return evidence.Evidence{
		ID: "SEC-PY_PATH_TRAVERSAL", RuleID: "python.ast/PY_PATH_TRAVERSAL", Title: "Path traversal",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "injection",
		Endpoint: ep, Line: &l, Evidence: "open(path)", Sink: "open(path)", Symbol: "handler",
		Confidence: models.ConfidenceHigh,
	}
}

// Matrix 8 and invariant 4: permuting detector output changes nothing — not
// the occurrence identities, not the IDs, not the presented findings, not the
// verdict.
func TestFinalize_DetectorOrderDoesNotChangeIdentityOrVerdict(t *testing.T) {
	evs := []evidence.Evidence{
		gsSecretEvidence("pkg/tests/helpers.py", "password"),
		gsSecretEvidence("pkg/zapp/db.py", "password"),
		gsSecretEvidence("pkg/app/db.py", "password"),
		gsHeaderEvidence("/a"), gsHeaderEvidence("/b"), gsHeaderEvidence("/c"),
		gsCodeEvidence("svc/views.py", 10), gsCodeEvidence(".github/scripts/x.py", 3),
	}
	want, wantCode := finalizeOnce(t, evs, scanOpts{})
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		perm := make([]evidence.Evidence, len(evs))
		for j, k := range rng.Perm(len(evs)) {
			perm[j] = evs[k]
		}
		got, code := finalizeOnce(t, perm, scanOpts{})
		if code != wantCode {
			t.Fatalf("permutation %d: verdict %d, want %d", i, code, wantCode)
		}
		if len(got) != len(want) {
			t.Fatalf("permutation %d: %d findings, want %d", i, len(got), len(want))
		}
		for j := range got {
			if got[j].ID != want[j].ID || got[j].Fingerprint != want[j].Fingerprint ||
				!reflect.DeepEqual(got[j].Occurrences, want[j].Occurrences) || got[j].Status != want[j].Status {
				t.Fatalf("permutation %d, finding %d differs:\n got %s %s %v %s\nwant %s %s %v %s", i, j,
					got[j].ID, got[j].Fingerprint, got[j].Occurrences, got[j].Status,
					want[j].ID, want[j].Fingerprint, want[j].Occurrences, want[j].Status)
			}
		}
	}
}

// Invariant 4: an occurrence's fingerprint is the same whether it is alone or
// grouped with others, and whichever occurrence is the primary.
func TestFinalize_GroupingDoesNotChangeOccurrenceIdentity(t *testing.T) {
	alone, _ := finalizeOnce(t, []evidence.Evidence{gsSecretEvidence("pkg/tests/helpers.py", "password")}, scanOpts{})
	grouped, _ := finalizeOnce(t, []evidence.Evidence{
		gsSecretEvidence("pkg/tests/helpers.py", "password"), gsSecretEvidence("pkg/app/db.py", "password"),
	}, scanOpts{})
	if len(alone) != 1 || len(grouped) != 1 || len(grouped[0].Occurrences) != 2 {
		t.Fatalf("setup: %v / %v", alone, grouped)
	}
	var fixtureInGroup string
	for _, o := range grouped[0].Occurrences {
		if o.Endpoint == "pkg/tests/helpers.py:2" {
			fixtureInGroup = o.Fingerprint
		}
	}
	if fixtureInGroup != alone[0].Fingerprint {
		t.Errorf("fixture identity changed when grouped: %s alone, %s grouped", alone[0].Fingerprint, fixtureInGroup)
	}
}

// Non-secret detectors share the pipeline: the same invariants hold for a
// grouped HTTP header finding and a grouped code finding.
func TestFinalize_NonSecretGroupedDetectorsAreOccurrenceScoped(t *testing.T) {
	t.Run("http header group: baseline", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "base.json")
		finalizeOnce(t, []evidence.Evidence{gsHeaderEvidence("/b"), gsHeaderEvidence("/c")}, scanOpts{saveBaseline: base})
		got, _ := finalizeOnce(t, []evidence.Evidence{gsHeaderEvidence("/a"), gsHeaderEvidence("/b"), gsHeaderEvidence("/c")}, scanOpts{baseline: base})
		if len(got) != 1 || got[0].Endpoint != "GET /a" || len(got[0].Occurrences) != 1 {
			t.Fatalf("want only GET /a new, got %+v", got)
		}
	})
	t.Run("http header group: path ignore", func(t *testing.T) {
		ign := writeIgnore(t, "ignore:\n  - endpoint: \"/public/**\"\n")
		got, _ := finalizeOnce(t, []evidence.Evidence{gsHeaderEvidence("/public/x"), gsHeaderEvidence("/private/y")}, scanOpts{ignore: ign})
		if len(got) != 1 || got[0].Endpoint != "GET /private/y" {
			t.Fatalf("want only GET /private/y, got %+v", got)
		}
	})
	t.Run("code finding group: baseline, new occurrence sorts first", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "base.json")
		finalizeOnce(t, []evidence.Evidence{gsCodeEvidence("svc/views.py", 10), gsCodeEvidence("svc/admin.py", 4)}, scanOpts{saveBaseline: base})
		got, code := finalizeOnce(t, []evidence.Evidence{
			gsCodeEvidence(".github/scripts/x.py", 3), gsCodeEvidence("svc/views.py", 10), gsCodeEvidence("svc/admin.py", 4),
		}, scanOpts{baseline: base})
		if len(got) != 1 || got[0].Endpoint != ".github/scripts/x.py:3" || len(got[0].Occurrences) != 1 {
			t.Fatalf("want only the new occurrence, got %+v", got)
		}
		if code != 1 {
			t.Errorf("new HIGH code finding: verdict %d, want 1", code)
		}
	})
	t.Run("code finding group: baseline, new occurrence sorts last", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "base.json")
		finalizeOnce(t, []evidence.Evidence{gsCodeEvidence("svc/admin.py", 4)}, scanOpts{saveBaseline: base})
		got, code := finalizeOnce(t, []evidence.Evidence{gsCodeEvidence("svc/admin.py", 4), gsCodeEvidence("zz/new.py", 7)}, scanOpts{baseline: base})
		if len(got) != 1 || got[0].Endpoint != "zz/new.py:7" || code != 1 {
			t.Fatalf("want only zz/new.py:7 blocking, got %+v (verdict %d)", got, code)
		}
	})
}

// An occurrence list a finding ARRIVES with (a plugin's, say) is not evidence:
// identity is the occurrence's own stamped fingerprint.
func TestFinalize_IncomingOccurrenceListIsNotTrusted(t *testing.T) {
	ev := gsSecretEvidence("pkg/zapp/db.py", "password")
	forged := strings.Repeat("0", 40)
	ev.Occurrences = []models.Occurrence{{Endpoint: "pkg/tests/helpers.py:2", Fingerprint: forged}}
	got, _ := finalizeOnce(t, []evidence.Evidence{ev}, scanOpts{})
	if len(got) != 1 || len(got[0].Occurrences) != 1 {
		t.Fatalf("got %+v", got)
	}
	if o := got[0].Occurrences[0]; o.Fingerprint == forged || o.Endpoint != "pkg/zapp/db.py:2" || o.Fingerprint != got[0].Fingerprint {
		t.Errorf("occurrence = %+v; want the finding's own stamped identity", o)
	}
}
