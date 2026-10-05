package targets

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func ptr(s string) *string { return &s }

// TestOWASPSkipsInBothLayers pins the v0.27 B3 invariant: OWASP must report
// ErrTargetSkipped from BOTH Scan() and Run(), and Run() must return a nil
// result — so no all-zero (0.0-recall) BenchmarkResult can ever be persisted
// to the baseline or fed to Compare(), even if a future refactor calls Run()
// without Scan() short-circuiting first.
func TestOWASPSkipsInBothLayers(t *testing.T) {
	o := NewOWASP()
	if _, err := o.Scan(context.Background(), "fendix"); !errors.Is(err, ErrTargetSkipped) {
		t.Errorf("Scan() should return ErrTargetSkipped, got %v", err)
	}
	res, err := o.Run(context.Background(), nil)
	if !errors.Is(err, ErrTargetSkipped) {
		t.Errorf("Run() should return ErrTargetSkipped, got %v", err)
	}
	if res != nil {
		t.Errorf("Run() must return a nil result when skipped, got %+v", res)
	}
}

func TestByName(t *testing.T) {
	for _, name := range []string{"owasp", "dvwa", "juiceshop"} {
		got, err := ByName(name)
		if err != nil {
			t.Fatalf("ByName(%q): %v", name, err)
		}
		if got.Name() != name {
			t.Errorf("ByName(%q).Name() = %q", name, got.Name())
		}
	}
	if _, err := ByName("nope"); err == nil {
		t.Error("ByName(nope): want error, got nil")
	}
}

func TestFindingMatches(t *testing.T) {
	header := models.Finding{Category: "headers", Title: "Missing Content-Security-Policy header", Endpoint: "http://x/"}
	tests := []struct {
		name string
		want ExpectedVuln
		f    models.Finding
		ok   bool
	}{
		{"type+title", ExpectedVuln{Type: "headers", Location: "Content-Security-Policy"}, header, true},
		{"type only", ExpectedVuln{Type: "headers"}, header, true},
		{"wrong type", ExpectedVuln{Type: "cors", Location: "Content-Security-Policy"}, header, false},
		{"title miss", ExpectedVuln{Type: "headers", Location: "X-Frame-Options"}, header, false},
		{"line match", ExpectedVuln{Type: "secrets", Location: "config.py"}, models.Finding{Category: "secrets", Line: ptr("config.py:14")}, true},
	}
	for _, tt := range tests {
		if got := findingMatches(tt.want, tt.f); got != tt.ok {
			t.Errorf("%s: findingMatches = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

func TestScore(t *testing.T) {
	ks := &KnownSet{
		Target: "t",
		Vulnerabilities: []ExpectedVuln{
			{ID: "A", Type: "headers", Location: "Content-Security-Policy"},
			{ID: "B", Type: "headers", Location: "X-Frame-Options"},
			{ID: "C", Type: "cors"},
		},
	}
	findings := []models.Finding{
		{Category: "headers", Title: "Missing Content-Security-Policy header"}, // hits A
		{Category: "data_exposure", Title: "Stack trace leaked"},               // matches nothing → FP
	}
	got := score("t", ks, findings, 5*time.Second, time.Unix(0, 0))
	if got.TruePos != 1 { // only A matched
		t.Errorf("TruePos = %d, want 1", got.TruePos)
	}
	if got.FalseNeg != 2 { // B and C unmatched
		t.Errorf("FalseNeg = %d, want 2", got.FalseNeg)
	}
	if got.FalsePos != 1 { // the data_exposure finding
		t.Errorf("FalsePos = %d, want 1", got.FalsePos)
	}
	if got.ScanDuration != 5*time.Second {
		t.Errorf("ScanDuration = %v, want 5s", got.ScanDuration)
	}
}

func TestCommittedGroundTruthFilesParse(t *testing.T) {
	// The committed JSON files must load and be non-empty — they are the
	// ground truth the baseline depends on. Paths are relative to this
	// package, so walk up to the repo root.
	for _, rel := range []string{
		"../../../../benchmarks/targets/dvwa-known.json",
		"../../../../benchmarks/targets/juiceshop-known.json",
	} {
		ks, err := loadKnownSet(rel)
		if err != nil {
			t.Fatalf("loadKnownSet(%s): %v", rel, err)
		}
		if len(ks.Vulnerabilities) == 0 {
			t.Errorf("%s: no vulnerabilities defined", rel)
		}
		for _, v := range ks.Vulnerabilities {
			if v.Type == "" {
				t.Errorf("%s: vuln %q has empty type", rel, v.ID)
			}
		}
	}
}

// TestOWASPSkeletonIsNotScoreable pins the v0.28 owasp-known.json as an inert
// SKELETON, not a corpus: it must parse but stay EMPTY (no vulnerabilities, no
// negatives). This guards two failure modes — a future dev populating it and
// silently leaving OWASP SKIPPED, or un-SKIPping against a half-labeled file.
// When the real deep-Java-taint phase lands, this test is replaced by the real
// FP-penalized scoring test in the SAME change that un-SKIPs owasp.go.
func TestOWASPSkeletonIsNotScoreable(t *testing.T) {
	rel := "../../../../benchmarks/targets/owasp-known.json"
	ks, err := loadKnownSet(rel)
	if err != nil {
		t.Fatalf("loadKnownSet(%s): %v", rel, err)
	}
	if len(ks.Vulnerabilities) != 0 {
		t.Errorf("owasp-known.json must stay an empty skeleton, got %d vulnerabilities — "+
			"populating it requires un-SKIPping owasp.go + the real scoring test (see _definition_of_done)", len(ks.Vulnerabilities))
	}
	if ks.Negatives != 0 {
		t.Errorf("owasp-known.json skeleton must have negatives=0, got %d", ks.Negatives)
	}
}
