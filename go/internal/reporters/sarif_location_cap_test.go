package reporters

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// RC-8 (second half) — a deduplicated finding emitted one SARIF location per
// affected endpoint. A rate-limit sweep over a large API produced a single
// result carrying ~883 logicalLocations: technically expressive, operationally
// unreadable, and heavy enough to matter on every consumer that parses it.
//
// The full set is not DISCARDED — working rule 3 — it moves into a structured
// property. What is capped is the location list, which exists for a human to
// navigate.

func sweepFinding(n int) models.Finding {
	eps := make([]string, n)
	for i := range eps {
		eps[i] = fmt.Sprintf("GET /api/resource/%d", i)
	}
	return models.Finding{
		ID: "SEC-001", Fingerprint: "fp-sweep", RuleID: "ratelimit.absent",
		Category: "rate_limiting",
		Title:    "No rate limiting observed within 20 requests",
		Severity: models.SeverityMedium, Source: models.SourceBlackbox,
		Endpoint: eps[0], AffectedEndpoints: eps,
		Evidence:   "Sent 20 rapid requests with no 429 response and no rate-limit headers. Scope note: this bounded burst cannot prove the absence of slower per-minute/per-hour limiters.",
		Confidence: models.ConfidenceMedium,
	}
}

func TestManyAffectedEndpointsDoNotExplodeIntoLocations(t *testing.T) {
	run := renderOne(t, sweepFinding(883))
	res := run["results"].([]any)[0].(map[string]any)
	locs := res["locations"].([]any)

	if len(locs) > sarifMaxLogicalLocations {
		t.Errorf("%d logicalLocations on one result — the cap is %d", len(locs), sarifMaxLogicalLocations)
	}
	if len(locs) == 0 {
		t.Error("all locations were dropped; a reader has nowhere to start")
	}
}

// Capping must never look like coverage. The full count and the full set both
// have to survive, or a truncated report reads as a complete one.
func TestTruncatedLocationsKeepTheFullAccounting(t *testing.T) {
	run := renderOne(t, sweepFinding(883))
	res := run["results"].([]any)[0].(map[string]any)
	props := res["properties"].(map[string]any)

	if got := props["affected_endpoint_count"]; got != float64(883) {
		t.Errorf("affected_endpoint_count = %v, want 883", got)
	}
	all, ok := props["affected_endpoints"].([]any)
	if !ok {
		t.Fatal("the full endpoint set was dropped rather than moved")
	}
	if len(all) != 883 {
		t.Errorf("affected_endpoints holds %d entries, want all 883", len(all))
	}
	if got := props["locations_truncated"]; got != true {
		t.Errorf("locations_truncated = %v; a truncated result must say so", got)
	}
}

// The message states the real scale, so the count is visible without opening
// the properties.
func TestMessageStatesTheRealScale(t *testing.T) {
	run := renderOne(t, sweepFinding(883))
	res := run["results"].([]any)[0].(map[string]any)
	msg := res["message"].(map[string]any)["text"].(string)

	if !strings.Contains(msg, "883") {
		t.Errorf("message does not state how many operations are affected: %q", msg)
	}
}

// A finding within the cap is completely unchanged — no truncation marker, no
// duplicated endpoint list, byte-for-byte what it was.
func TestSmallFindingsAreUntouched(t *testing.T) {
	run := renderOne(t, sweepFinding(3))
	res := run["results"].([]any)[0].(map[string]any)

	if got := len(res["locations"].([]any)); got != 3 {
		t.Errorf("a 3-endpoint finding rendered %d locations", got)
	}
	props, _ := res["properties"].(map[string]any)
	if props != nil {
		if _, ok := props["locations_truncated"]; ok {
			t.Error("an untruncated result carries a truncation marker")
		}
		if _, ok := props["affected_endpoints"]; ok {
			t.Error("an untruncated result duplicates its endpoint list into properties")
		}
	}
}

// The scientific caveat must survive the compaction — it is the reason the
// finding is honest.
func TestCompactionPreservesTheBoundedBurstCaveat(t *testing.T) {
	run := renderOne(t, sweepFinding(883))
	res := run["results"].([]any)[0].(map[string]any)
	props := res["properties"].(map[string]any)

	if ev, _ := props["evidence"].(string); !strings.Contains(ev, "cannot prove the absence") {
		t.Errorf("compaction dropped the scope caveat: %q", ev)
	}
}
