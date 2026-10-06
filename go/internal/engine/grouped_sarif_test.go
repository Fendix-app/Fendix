package engine

// SARIF identity boundary (follow-up to grouped_suppression_test.go).
//
// GitHub Code Scanning keys an alert — and any dismissal of it — on the
// result's partialFingerprints. These tests pin that a SARIF result's identity
// is always ONE occurrence's: occurrence A's tracking identity can never come
// to stand for a different occurrence B because Fendix groups A and B for
// presentation.

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// sarifOcc is what an alert tracker sees of one result.
type sarifOcc struct {
	location    string // uri:line, or the logical endpoint
	fingerprint string
	snippet     string
	findingID   string
	count       int
	level       string
}

func sarifScan(t *testing.T, root string, o scanOpts) (int, []sarifOcc) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.sarif")
	cfg := &models.ScanConfig{
		CodePath: root, FailOn: "HIGH", Format: "sarif", OutputPath: out,
		EnforceConfidence: true, DeescalateTests: true,
		BaselinePath: o.baseline, IgnorePath: o.ignore,
	}
	code := NewOrchestrator(cfg, "test").Run(context.Background())
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading SARIF: %v", err)
	}
	return code, parseSARIFOccurrences(t, data, "hardcoded-password")
}

// parseSARIFOccurrences returns the results whose ruleId contains ruleFrag,
// sorted by location.
func parseSARIFOccurrences(t *testing.T, data []byte, ruleFrag string) []sarifOcc {
	t.Helper()
	var log reporters.SARIFLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("parsing SARIF: %v", err)
	}
	var out []sarifOcc
	for _, r := range log.Runs[0].Results {
		if !strings.Contains(r.RuleID, ruleFrag) {
			continue
		}
		o := sarifOcc{fingerprint: r.PartialFingerprints[models.FingerprintAlgorithm], level: r.Level}
		if len(r.Locations) != 1 {
			t.Fatalf("result %s has %d locations; an occurrence result has exactly one", r.RuleID, len(r.Locations))
		}
		loc := r.Locations[0]
		switch {
		case loc.PhysicalLocation != nil:
			o.location = loc.PhysicalLocation.ArtifactLocation.URI
			if reg := loc.PhysicalLocation.Region; reg != nil {
				o.location += ":" + strconv.Itoa(reg.StartLine)
				if reg.Snippet != nil {
					o.snippet = reg.Snippet.Text
				}
			}
		case len(loc.LogicalLocations) > 0:
			o.location = loc.LogicalLocations[0].Name
		}
		if r.Properties != nil {
			o.findingID, o.count = r.Properties.FindingID, r.Properties.OccurrenceCount
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].location < out[j].location })
	return out
}

func byLocation(occ []sarifOcc, loc string) (sarifOcc, bool) {
	for _, o := range occ {
		if o.location == loc {
			return o, true
		}
	}
	return sarifOcc{}, false
}

// Matrix 1–7 (and 9's ordering half): fixture A alone, then production B joins
// A's presentation group, with B sorting before and after A.
func TestSARIF_JoiningOccurrenceGetsItsOwnIdentity(t *testing.T) {
	const fixture = "pkg/tests/helpers.py:2"

	// B scanned on its own: the identity B must keep whatever it groups with.
	aloneIdentity := map[string]string{}
	for _, dir := range []string{"aaa", "app", "zapp", "zzz"} {
		prod := "pkg/" + dir + "/db.py"
		_, alone := sarifScan(t, repoFiles(t, map[string]string{prod: prodCredential}), scanOpts{})
		if len(alone) != 1 || alone[0].fingerprint == "" {
			t.Fatalf("%s alone: %+v", dir, alone)
		}
		aloneIdentity[dir] = alone[0].fingerprint
	}

	// 1. Fixture occurrence A produces SARIF result A.
	root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential})
	_, before := sarifScan(t, root, scanOpts{})
	if len(before) != 1 || before[0].location != fixture || before[0].fingerprint == "" {
		t.Fatalf("fixture alone: %+v", before)
	}
	fixtureID := before[0].fingerprint

	for _, dir := range []string{"aaa", "app", "zapp", "zzz"} {
		t.Run(dir, func(t *testing.T) {
			prodFile := "pkg/" + dir + "/db.py"
			root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, prodFile: prodCredential})

			// The two occurrences ARE one Fendix finding (the precondition).
			_, rep := codeScan(t, root, scanOpts{})
			if pw := passwordFindings(rep); len(pw) != 1 || len(pw[0].Occurrences) != 2 {
				t.Fatalf("precondition: want one grouped finding with 2 occurrences, got %+v", pw)
			}

			_, got := sarifScan(t, root, scanOpts{})
			// 3. Independently identifiable A and B results.
			if len(got) != 2 {
				t.Fatalf("want 2 SARIF results (A and B), got %d: %+v", len(got), got)
			}
			a, okA := byLocation(got, fixture)
			b, okB := byLocation(got, prodFile+":2")
			if !okA || !okB {
				t.Fatalf("results %+v; want one at %s and one at %s:2", got, fixture, prodFile)
			}
			// 4/6. Different identities; B does not carry A's.
			if a.fingerprint == b.fingerprint || b.fingerprint == fixtureID {
				t.Errorf("B shares an identity with A: A=%s B=%s", a.fingerprint, b.fingerprint)
			}
			// A keeps the identity it had alone (an existing dismissal of A
			// stays on A) ...
			if a.fingerprint != fixtureID {
				t.Errorf("A's identity changed when B joined: %s -> %s", fixtureID, a.fingerprint)
			}
			// 7. ... and B's identity is the one it has alone, whatever sorts first.
			if b.fingerprint != aloneIdentity[dir] {
				t.Errorf("B's identity depends on grouping: alone %s, grouped %s", aloneIdentity[dir], b.fingerprint)
			}
			// 5. B points at production, and never shows the fixture's evidence.
			if strings.Contains(b.snippet, "t@example.com") || strings.Contains(b.snippet, "Fixture") {
				t.Errorf("B's snippet is the fixture's: %q", b.snippet)
			}
			if strings.Contains(a.snippet, "Pr0d") || strings.Contains(a.snippet, "svc") {
				t.Errorf("A's snippet is production's: %q", a.snippet)
			}
			// Both name their presentation group, which is presentation only.
			if a.findingID == "" || a.findingID != b.findingID || a.count != 2 || b.count != 2 {
				t.Errorf("group reference: A=%+v B=%+v", a, b)
			}
		})
	}
}

// Matrix 9: with A suppressed, SARIF holds exactly B, under B's own identity.
func TestSARIF_SuppressedFixtureLeavesOnlyProduction(t *testing.T) {
	ign := "ignore:\n  - endpoint: \"**/tests/**\"\n"
	for _, dir := range []string{"app", "zapp"} {
		t.Run(dir, func(t *testing.T) {
			prodFile := "pkg/" + dir + "/db.py"
			_, alone := sarifScan(t, repoFiles(t, map[string]string{prodFile: prodCredential}), scanOpts{})
			root := repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential, prodFile: prodCredential})

			for name, o := range map[string]scanOpts{"ignore": {ignore: writeIgnore(t, ign)}} {
				code, got := sarifScan(t, root, o)
				if code != 1 || len(got) != 1 {
					t.Fatalf("%s: exit %d, results %+v; want exit 1 and only B", name, code, got)
				}
				if got[0].location != prodFile+":2" || got[0].fingerprint != alone[0].fingerprint || got[0].level != "error" {
					t.Errorf("%s: %+v; want B at %s:2 with identity %s, level error", name, got[0], prodFile, alone[0].fingerprint)
				}
				if strings.Contains(got[0].snippet, "t@example.com") {
					t.Errorf("%s: B shows the suppressed fixture's evidence", name)
				}
			}

			base := filepath.Join(t.TempDir(), "base.json")
			codeScan(t, repoFiles(t, map[string]string{"pkg/tests/helpers.py": fixtureCredential}), scanOpts{saveBaseline: base})
			code, got := sarifScan(t, root, scanOpts{baseline: base})
			if code != 1 || len(got) != 1 || got[0].fingerprint != alone[0].fingerprint {
				t.Errorf("baseline: exit %d, %+v; want only B (%s)", code, got, alone[0].fingerprint)
			}
		})
	}
}

// Matrix 10, 11: identities are stable across scans; a new occurrence adds an
// identity without disturbing the known ones.
func TestSARIF_IdentitiesStableAcrossScans(t *testing.T) {
	files := map[string]string{"svc/a/tests/helpers.py": fixtureCredential, "svc/b/tests/helpers.py": fixtureCredential}
	root := repoFiles(t, files)
	_, first := sarifScan(t, root, scanOpts{})
	_, second := sarifScan(t, root, scanOpts{})
	if len(first) != 2 || !reflect.DeepEqual(first, second) {
		t.Fatalf("two known occurrences changed between identical scans:\n%+v\n%+v", first, second)
	}

	// A new occurrence that sorts FIRST (would become the group's primary).
	if err := os.MkdirAll(filepath.Join(root, "svc/0new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "svc/0new/db.py"), []byte(prodCredential), 0o644); err != nil {
		t.Fatal(err)
	}
	_, third := sarifScan(t, root, scanOpts{})
	if len(third) != 3 {
		t.Fatalf("want 3 results, got %+v", third)
	}
	for _, known := range first {
		got, ok := byLocation(third, known.location)
		if !ok || got.fingerprint != known.fingerprint {
			t.Errorf("known occurrence %s lost its identity: %+v", known.location, got)
		}
	}
	newer, _ := byLocation(third, "svc/0new/db.py:2")
	for _, known := range first {
		if newer.fingerprint == known.fingerprint {
			t.Errorf("the new occurrence took known identity %s", known.fingerprint)
		}
	}
}

func finalizeSARIF(t *testing.T, evs []evidence.Evidence, ruleFrag string) []sarifOcc {
	t.Helper()
	out := filepath.Join(t.TempDir(), "r.sarif")
	cfg := &models.ScanConfig{FailOn: "HIGH", Format: "sarif", OutputPath: out, EnforceConfidence: true, DeescalateTests: true}
	in := make([]evidence.Evidence, len(evs))
	copy(in, evs)
	if _, _, ec := NewOrchestrator(cfg, "test").finalize(in, reporters.ScanMetadata{StartedAt: time.Unix(0, 0), Version: "test", Mode: "whitebox", FingerprintAlgorithm: models.FingerprintAlgorithm}); ec != 0 {
		t.Fatalf("finalize exit %d", ec)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return parseSARIFOccurrences(t, data, ruleFrag)
}

// Matrix 8: permuting detector output changes no SARIF identity.
func TestSARIF_DetectorOrderDoesNotChangeIdentities(t *testing.T) {
	evs := []evidence.Evidence{
		gsSecretEvidence("pkg/tests/helpers.py", "password"),
		gsSecretEvidence("pkg/zapp/db.py", "password"),
		gsSecretEvidence("pkg/app/db.py", "password"),
	}
	want := finalizeSARIF(t, evs, "hardcoded-password")
	if len(want) != 3 {
		t.Fatalf("want 3 occurrence results, got %+v", want)
	}
	for _, o := range want {
		if o.fingerprint == "" {
			t.Fatalf("result without identity: %+v", want)
		}
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 15; i++ {
		perm := make([]evidence.Evidence, len(evs))
		for j, k := range rng.Perm(len(evs)) {
			perm[j] = evs[k]
		}
		if got := finalizeSARIF(t, perm, "hardcoded-password"); !reflect.DeepEqual(got, want) {
			t.Fatalf("permutation %d changed SARIF identities:\n got %+v\nwant %+v", i, got, want)
		}
	}
}

// Matrix 12: a non-secret grouped detector takes the same path — an HTTP
// header group and a code finding group.
func TestSARIF_NonSecretGroupsAreOccurrenceResults(t *testing.T) {
	t.Run("http header group", func(t *testing.T) {
		alone := finalizeSARIF(t, []evidence.Evidence{gsHeaderEvidence("/b")}, "missing-csp")
		got := finalizeSARIF(t, []evidence.Evidence{gsHeaderEvidence("/a"), gsHeaderEvidence("/b"), gsHeaderEvidence("/c")}, "missing-csp")
		if len(got) != 3 {
			t.Fatalf("want one result per endpoint, got %+v", got)
		}
		seen := map[string]bool{}
		for _, o := range got {
			if o.fingerprint == "" || seen[o.fingerprint] {
				t.Errorf("results share or lack identity: %+v", got)
			}
			seen[o.fingerprint] = true
		}
		b, _ := byLocation(got, "GET /b")
		if b.fingerprint != alone[0].fingerprint {
			t.Errorf("GET /b identity depends on its group: alone %s, grouped %s", alone[0].fingerprint, b.fingerprint)
		}
	})
	t.Run("code finding group", func(t *testing.T) {
		got := finalizeSARIF(t, []evidence.Evidence{gsCodeEvidence("svc/views.py", 10), gsCodeEvidence(".github/scripts/x.py", 3)}, "path-traversal")
		if len(got) != 2 || got[0].fingerprint == "" || got[0].fingerprint == got[1].fingerprint {
			t.Fatalf("want two independently identified results, got %+v", got)
		}
	})
}
