package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// RC-9 — run.automationDetails.id is the category GitHub Code Scanning
// partitions alerts by. Every Fendix run published under one constant
// "fendix/scan", so a code-only scan and a live DAST scan of the same
// repository landed in one bucket: whichever uploaded last cleared the other's
// alerts, because an upload with no findings for a category means "everything
// in this category is fixed".
//
// The id must be deterministic and stable across equivalent runs, and distinct
// exactly where the analyses are genuinely different.

func automationID(t *testing.T, meta ScanMetadata, findings ...models.Finding) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Runs[0].AutomationDetails == nil {
		t.Fatal("no automationDetails — GitHub cannot categorise the run")
	}
	return log.Runs[0].AutomationDetails.ID
}

func TestAutomationIDDistinguishesAnalysisCategories(t *testing.T) {
	seen := map[string]string{}
	for _, mode := range []string{"whitebox", "blackbox", "hybrid", "import"} {
		id := automationID(t, ScanMetadata{Version: "test", Mode: mode})
		if prior, clash := seen[id]; clash {
			t.Errorf("mode %q and mode %q share automation id %q — one run's upload will clear the other's alerts",
				mode, prior, id)
		}
		seen[id] = mode
	}
}

// Deterministic: the same analysis re-run must land in the same bucket, or
// every scan opens a fresh alert set and nothing is ever "fixed".
func TestAutomationIDIsStableAcrossEquivalentRuns(t *testing.T) {
	meta := ScanMetadata{Version: "test", Mode: "whitebox", Target: "/src"}
	first := automationID(t, meta)
	for i := range 5 {
		if got := automationID(t, meta); got != first {
			t.Fatalf("run %d produced %q, want %q", i+2, got, first)
		}
	}
}

// Things that legitimately vary between two runs of the SAME analysis must not
// move the category: a new engine build, a longer scan, more endpoints, a
// different finding count.
func TestAutomationIDIgnoresRunToRunVariation(t *testing.T) {
	base := ScanMetadata{Version: "2.1.1", Mode: "whitebox", Target: "/src", Duration: "3s", EndpointsCount: 10}
	want := automationID(t, base)

	variants := []ScanMetadata{
		{Version: "2.2.0", Mode: "whitebox", Target: "/src", Duration: "3s", EndpointsCount: 10},
		{Version: "2.1.1", Mode: "whitebox", Target: "/src", Duration: "91s", EndpointsCount: 10},
		{Version: "2.1.1", Mode: "whitebox", Target: "/src", Duration: "3s", EndpointsCount: 883},
	}
	for i, v := range variants {
		f := models.Finding{ID: "SEC-001", Category: "secrets", Title: "x", Endpoint: "a.py:1"}
		if got := automationID(t, v, f); got != want {
			t.Errorf("variant %d moved the category: %q, want %q", i, got, want)
		}
	}
}

// No timestamps, no UUIDs, no counters: an id made unique per run defeats the
// purpose, because GitHub can never match this run's alerts to the last one's.
func TestAutomationIDCarriesNoPerRunEntropy(t *testing.T) {
	meta := ScanMetadata{Version: "test", Mode: "hybrid", Target: "https://example.test"}
	id := automationID(t, meta)
	for _, digit := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
		if bytes.Contains([]byte(id), []byte(digit)) {
			t.Errorf("automation id %q contains a digit — check it is not a timestamp or counter", id)
		}
	}
}

// A run with no mode (an older caller, or `fendix report --input` over a
// pre-mode report) must still get the original category, so existing GitHub
// alert sets are not re-partitioned for reports that never had a mode.
func TestAutomationIDFallsBackToTheOriginalCategory(t *testing.T) {
	if got := automationID(t, ScanMetadata{Version: "test"}); got != "fendix/scan" {
		t.Errorf("unmoded run got %q, want the original fendix/scan", got)
	}
}
