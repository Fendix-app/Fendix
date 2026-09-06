package pip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/confidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// gisAdvisory is a django advisory whose own summary names contrib.gis —
// the self-evidencing shape the applicability catalog's package tier
// requires before it will scope anything.
func gisAdvisory() []osvVuln {
	return []osvVuln{{
		ID:      "PYSEC-2026-9001",
		Summary: "Denial of service in django.contrib.gis geometry parsing",
		Aliases: []string{"CVE-2026-9001"},
		Affected: []osvAffected{{Ranges: []osvRange{{
			Type:   "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "0"}, {Fixed: "5.2.17"}},
		}}}},
	}}
}

func scanWithGisAdvisory(t *testing.T, sourceFile, sourceBody string) []evidence.Evidence {
	t.Helper()
	ts := newFakeOSVServer(t, map[string][]osvVuln{"django": gisAdvisory()})
	defer ts.Close()
	prev := OSVBaseURL
	OSVBaseURL = ts.URL
	defer func() { OSVBaseURL = prev }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("django==5.2.16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, sourceFile)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(sourceBody), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1", len(findings))
	}
	return findings
}

// TestScan_DeescalatesAnAdvisoryWhoseComponentIsNeverImported is the FIX-14
// wiring test: the scanner's own call to applicability.Resolve, exercised
// end to end through Scan rather than by calling Resolve directly.
//
// Rule 3 is the assertion that matters: the finding is still there, at the
// same id and severity, with its original evidence text intact and one
// sentence appended. Nothing is suppressed and no path is excluded.
func TestScan_DeescalatesAnAdvisoryWhoseComponentIsNeverImported(t *testing.T) {
	findings := scanWithGisAdvisory(t, "api/views.py", "from django.http import JsonResponse\n")
	f := findings[0]

	if f.ID != "SEC-DEPS-CVE_2026_9001" {
		t.Errorf("ID = %q; the de-escalation must not touch identity", f.ID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; de-escalation moves CONFIDENCE, not severity", f.Severity)
	}
	if !f.ComponentNotImported {
		t.Fatal("ComponentNotImported not set although nothing in the tree imports django.contrib.gis")
	}
	if !strings.Contains(f.Evidence, "django==5.2.16: Denial of service in django.contrib.gis") {
		t.Errorf("the original evidence text was not preserved: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "affected component not imported (django.contrib.gis)") {
		t.Errorf("annotation missing: %q", f.Evidence)
	}
	if !strings.Contains(f.Fix, "django==5.2.17") {
		t.Errorf("Fix = %q; the upgrade advice is unchanged by de-escalation", f.Fix)
	}

	// The observable effect, end to end: HIGH band without the flag,
	// MEDIUM with it. Assert on the confidence SCORE/BAND, which is what
	// moved — NOT on Finding.Confidence, which buildFinding hard-codes to
	// HIGH and which this change deliberately does not touch.
	full := f
	full.ComponentNotImported = false
	if got, want := confidence.Score(full).Band, models.ConfidenceHigh; got != want {
		t.Fatalf("baseline band = %q; this test's premise is that a dep finding starts HIGH", got)
	}
	if got := confidence.Score(f); got.Band != models.ConfidenceMedium {
		t.Errorf("band = %q (%d); want MEDIUM", got.Band, got.Value)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("Finding.Confidence = %q; want HIGH — it is a different field from the confidence band", f.Confidence)
	}
}

func TestScan_KeepsFullConfidenceWhenTheComponentIsImported(t *testing.T) {
	findings := scanWithGisAdvisory(t, "maps/views.py", "from django.contrib.gis.geos import Point\n")
	f := findings[0]

	if f.ComponentNotImported {
		t.Error("ComponentNotImported set although the tree imports django.contrib.gis")
	}
	if strings.Contains(f.Evidence, "affected component not imported") {
		t.Errorf("evidence was annotated anyway: %q", f.Evidence)
	}
	if got := confidence.Score(f); got.Band != models.ConfidenceHigh {
		t.Errorf("band = %q (%d); want HIGH", got.Band, got.Value)
	}
}

// TestScan_UncataloguedAdvisoryIsUntouched: the catalog is deliberately
// small, and a package it does not cover must cost nothing and change
// nothing.
func TestScan_UncataloguedAdvisoryIsUntouched(t *testing.T) {
	ts := newFakeOSVServer(t, map[string][]osvVuln{"flask": {{
		ID:      "PYSEC-2026-9002",
		Summary: "Some flask flaw",
		Affected: []osvAffected{{Ranges: []osvRange{{
			Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "2.0.2"}}}}}},
	}}})
	defer ts.Close()
	prev := OSVBaseURL
	OSVBaseURL = ts.URL
	defer func() { OSVBaseURL = prev }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1", len(findings))
	}
	if findings[0].ComponentNotImported {
		t.Error("an uncatalogued advisory was de-escalated")
	}
	if !strings.HasSuffix(findings[0].Evidence, "Some flask flaw") {
		t.Errorf("evidence was annotated: %q", findings[0].Evidence)
	}
}
