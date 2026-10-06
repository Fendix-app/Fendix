package reporters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

const (
	occFixtureFP = "a2718025fd74aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	occProdFP    = "a2c381fcb888bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// groupedSecret is the reproduction's grouped finding as the engine emits it:
// the fixture sorts first, so it is the primary.
func groupedSecret() models.Finding {
	line := "pkg/tests/helpers.py:2"
	return models.Finding{
		ID: "SEC-001", RuleID: "secrets/HARDCODED_PASSWORD", Fingerprint: occFixtureFP,
		Title: "Hardcoded password", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Category: "secrets", Endpoint: "pkg/tests/helpers.py:2", Line: &line,
		AffectedEndpoints: []string{"pkg/tests/helpers.py:2", "pkg/zapp/db.py:2"},
		Occurrences: []models.Occurrence{
			{Endpoint: "pkg/tests/helpers.py:2", Fingerprint: occFixtureFP},
			{Endpoint: "pkg/zapp/db.py:2", Fingerprint: occProdFP},
		},
		Evidence:   `il="t@example.com", password="[REDACTED len=16 sha256:fedaa870...]")`,
		Fix:        "Move the credential to a secret store.",
		References: []string{"CWE-798"}, Confidence: models.ConfidenceHigh, Status: "BLOCK",
		ConfidenceScore: 90, ConfidenceBand: "HIGH",
	}
}

func renderOccSARIF(t *testing.T, findings []models.Finding) (SARIFLog, []byte) {
	t.Helper()
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "repo", StartedAt: time.Unix(0, 0).UTC(), Version: "golden", Mode: "whitebox", FingerprintAlgorithm: models.FingerprintAlgorithm}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	return log, buf.Bytes()
}

func resultAt(t *testing.T, log SARIFLog, uri string) SARIFResult {
	t.Helper()
	for _, r := range log.Runs[0].Results {
		if len(r.Locations) == 1 && r.Locations[0].PhysicalLocation != nil &&
			r.Locations[0].PhysicalLocation.ArtifactLocation.URI == uri {
			return r
		}
	}
	t.Fatalf("no result at %s", uri)
	return SARIFResult{}
}

func TestSARIF_GroupedFindingIsOneResultPerOccurrence(t *testing.T) {
	log, _ := renderOccSARIF(t, []models.Finding{groupedSecret()})
	if n := len(log.Runs[0].Results); n != 2 {
		t.Fatalf("want 2 results, got %d", n)
	}
	if n := len(log.Runs[0].Tool.Driver.Rules); n != 1 {
		t.Errorf("rules are per check, not per occurrence: got %d", n)
	}
	a, b := resultAt(t, log, "pkg/tests/helpers.py"), resultAt(t, log, "pkg/zapp/db.py")
	if got := a.PartialFingerprints["fendix/v2"]; got != occFixtureFP {
		t.Errorf("A identity = %q", got)
	}
	if got := b.PartialFingerprints["fendix/v2"]; got != occProdFP {
		t.Errorf("B identity = %q; it must be B's own, never the group primary's", got)
	}
	if a.Locations[0].PhysicalLocation.Region.Snippet == nil {
		t.Error("A (the occurrence the evidence came from) lost its snippet")
	}
	if reg := b.Locations[0].PhysicalLocation.Region; reg == nil || reg.StartLine != 2 || reg.Snippet != nil {
		t.Errorf("B region = %+v; want line 2 and no borrowed snippet", reg)
	}
	if b.Properties == nil || b.Properties.Evidence != "" || b.Properties.FindingID != "SEC-001" || b.Properties.OccurrenceCount != 2 {
		t.Errorf("B properties = %+v", b.Properties)
	}
	if !strings.Contains(b.Message.Text, "pkg/zapp/db.py:2") {
		t.Errorf("B message %q does not name B's location", b.Message.Text)
	}
	if a.RuleID != b.RuleID || a.Level != "error" || b.Level != "error" {
		t.Errorf("rule/level: A=%s/%s B=%s/%s", a.RuleID, a.Level, b.RuleID, b.Level)
	}
}

// The proof travels with the occurrence it belongs to.
func TestSARIF_ProofStaysWithItsOccurrence(t *testing.T) {
	f := groupedSecret()
	f.Category, f.RuleID, f.Title = "injection", "python.ast/PY_PATH_TRAVERSAL", "Path traversal"
	f.TaintChain = []models.TaintLink{{File: "pkg/zapp/db.py", Line: 1, Expr: "request.args"}, {File: "pkg/zapp/db.py", Line: 2, Expr: "open(p)"}}
	f.Reachable = true
	log, _ := renderOccSARIF(t, []models.Finding{f})
	a, b := resultAt(t, log, "pkg/tests/helpers.py"), resultAt(t, log, "pkg/zapp/db.py")
	if len(a.CodeFlows) != 0 || (a.Properties != nil && a.Properties.Reachable) {
		t.Error("the fixture occurrence carries production's taint proof")
	}
	if len(b.CodeFlows) != 1 || b.Properties == nil || !b.Properties.Reachable {
		t.Error("the production occurrence lost its own taint proof")
	}
}

// A grouped finding from a report that predates occurrences cannot be split
// by identity; it renders grouped, but its primary's fingerprint must not
// become the identity of a result that stands for several occurrences.
func TestSARIF_LegacyGroupPublishesNoGroupIdentity(t *testing.T) {
	f := groupedSecret()
	f.Occurrences = nil
	log, _ := renderOccSARIF(t, []models.Finding{f})
	if n := len(log.Runs[0].Results); n != 1 {
		t.Fatalf("legacy group: want 1 result, got %d", n)
	}
	if fp := log.Runs[0].Results[0].PartialFingerprints; len(fp) != 0 {
		t.Errorf("legacy group published a group identity: %v", fp)
	}

	// A legacy single-location finding keeps its identity.
	f.AffectedEndpoints = nil
	log, _ = renderOccSARIF(t, []models.Finding{f})
	if got := log.Runs[0].Results[0].PartialFingerprints["fendix/v2"]; got != occFixtureFP {
		t.Errorf("single-location legacy finding identity = %q", got)
	}
}

// A single-occurrence finding renders exactly as it did before occurrences.
func TestSARIF_SingleOccurrenceUnchanged(t *testing.T) {
	f := groupedSecret()
	f.AffectedEndpoints = nil
	f.Occurrences = f.Occurrences[:1]
	_, with := renderOccSARIF(t, []models.Finding{f})
	f.Occurrences = nil
	_, without := renderOccSARIF(t, []models.Finding{f})
	if !bytes.Equal(with, without) {
		t.Error("a single-occurrence finding renders differently with its occurrence listed")
	}
}

// Golden contract for the reproduction's grouped finding.
func TestSARIF_GroupedOccurrencesGolden(t *testing.T) {
	_, got := renderOccSARIF(t, []models.Finding{groupedSecret()})
	golden := filepath.Join("testdata", "sarif_grouped_occurrences.golden.sarif")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 after reviewing the contract)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SARIF for a grouped finding changed; review and run UPDATE_GOLDEN=1 go test ./internal/reporters -run TestSARIF_GroupedOccurrencesGolden\n%s", got)
	}
}
