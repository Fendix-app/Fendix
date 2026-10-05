package engine

import (
	"reflect"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestDeduplicate_GroupsIdenticalFindings is the primary case from the
// 2026-04-28 evaluation: a passive header check fired on every endpoint,
// producing N copies of the same finding. After dedup, we expect one
// finding with N affected endpoints.
func TestDeduplicate_GroupsIdenticalFindings(t *testing.T) {
	endpoints := []string{
		"GET /api/users",
		"GET /api/posts",
		"GET /api/orders",
		"POST /api/login",
	}
	findings := make([]models.Finding, 0, len(endpoints))
	for _, ep := range endpoints {
		findings = append(findings, models.Finding{
			Title:      "Missing Content-Security-Policy header",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "headers",
			Endpoint:   ep,
			Confidence: models.ConfidenceHigh,
		})
	}

	out := Deduplicate(findings)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(out))
	}
	if len(out[0].AffectedEndpoints) != 4 {
		t.Errorf("expected AffectedEndpoints with 4 entries, got %d: %v",
			len(out[0].AffectedEndpoints), out[0].AffectedEndpoints)
	}
	for _, ep := range endpoints {
		found := false
		for _, got := range out[0].AffectedEndpoints {
			if got == ep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing endpoint %q in AffectedEndpoints %v", ep, out[0].AffectedEndpoints)
		}
	}
}

// TestDeduplicate_SingletonHasNoAffectedEndpoints: when a finding only ever
// occurs once, AffectedEndpoints stays nil — the existing Endpoint field is
// authoritative and listing it again would just bloat the JSON output.
func TestDeduplicate_SingletonHasNoAffectedEndpoints(t *testing.T) {
	in := []models.Finding{
		{Title: "AWS Access Key ID hardcoded", Severity: models.SeverityCritical, Category: "secrets", Endpoint: "config.py:12"},
	}
	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].AffectedEndpoints != nil {
		t.Errorf("singleton must not set AffectedEndpoints, got %v", out[0].AffectedEndpoints)
	}
}

// TestDeduplicate_DifferentSeverityNotMerged: same title + category but
// different severities are different findings (e.g. a Medium and a High
// version of the same check class). Don't merge them — the user needs to
// see both ranks.
func TestDeduplicate_DifferentSeverityNotMerged(t *testing.T) {
	in := []models.Finding{
		{Title: "Weak header", Category: "headers", Severity: models.SeverityMedium, Endpoint: "/a"},
		{Title: "Weak header", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/b"},
	}
	out := Deduplicate(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (severity differs), got %d", len(out))
	}
}

// TestDeduplicate_ReferencesUnioned: when N findings carry overlapping
// reference lists (CWE/OWASP IDs), the merged finding should hold the
// dedup'd union — sorted, no repeats.
func TestDeduplicate_ReferencesUnioned(t *testing.T) {
	in := []models.Finding{
		{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/1", References: []string{"CWE-89", "OWASP-A03"}},
		{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/2", References: []string{"OWASP-A03", "CWE-20"}},
	}
	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped, got %d", len(out))
	}
	want := []string{"CWE-20", "CWE-89", "OWASP-A03"}
	if !reflect.DeepEqual(out[0].References, want) {
		t.Errorf("References = %v, want %v", out[0].References, want)
	}
}

// TestDeduplicate_PicksHighestConfidence: a group containing both MEDIUM
// and HIGH confidence findings should report HIGH — the finding has been
// confirmed at higher confidence on at least one endpoint.
func TestDeduplicate_PicksHighestConfidence(t *testing.T) {
	in := []models.Finding{
		{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/1", Confidence: models.ConfidenceMedium},
		{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/2", Confidence: models.ConfidenceHigh},
		{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/3", Confidence: models.ConfidenceLow},
	}
	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped, got %d", len(out))
	}
	if out[0].Confidence != models.ConfidenceHigh {
		t.Errorf("Confidence = %s, want HIGH", out[0].Confidence)
	}
}

// TestDeduplicate_SourcePromotion: a group with mixed sources should
// promote to the strongest signal — `correlated` always wins, then
// `blackbox`, then `whitebox`. (In practice the Correlator runs first and
// merges hybrid pairs into `correlated` already, but dedup must not
// regress that signal.)
func TestDeduplicate_SourcePromotion(t *testing.T) {
	tests := []struct {
		name string
		in   []models.Source
		want models.Source
	}{
		{"correlated wins", []models.Source{models.SourceWhitebox, models.SourceCorrelated, models.SourceBlackbox}, models.SourceCorrelated},
		{"blackbox over whitebox", []models.Source{models.SourceWhitebox, models.SourceBlackbox}, models.SourceBlackbox},
		{"all whitebox stays whitebox", []models.Source{models.SourceWhitebox, models.SourceWhitebox}, models.SourceWhitebox},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := make([]models.Finding, len(tt.in))
			for i, s := range tt.in {
				fs[i] = models.Finding{
					Title: "X", Category: "c", Severity: models.SeverityHigh,
					Endpoint: string(rune('a' + i)), Source: s,
				}
			}
			out := Deduplicate(fs)
			if len(out) != 1 {
				t.Fatalf("expected 1, got %d", len(out))
			}
			if out[0].Source != tt.want {
				t.Errorf("Source = %s, want %s", out[0].Source, tt.want)
			}
		})
	}
}

// TestDeduplicate_PreservesOrder: the relative ordering of distinct groups
// in the output matches the order in which each group's first member
// appeared in the input. Stable ordering is what makes downstream
// SEC-NNN ID assignment deterministic.
func TestDeduplicate_PreservesOrder(t *testing.T) {
	in := []models.Finding{
		{Title: "A", Category: "c", Severity: models.SeverityHigh, Endpoint: "/1"},
		{Title: "B", Category: "c", Severity: models.SeverityHigh, Endpoint: "/2"},
		{Title: "A", Category: "c", Severity: models.SeverityHigh, Endpoint: "/3"}, // joins A
		{Title: "C", Category: "c", Severity: models.SeverityHigh, Endpoint: "/4"},
	}
	out := Deduplicate(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 deduped (A, B, C), got %d", len(out))
	}
	titles := []string{out[0].Title, out[1].Title, out[2].Title}
	want := []string{"A", "B", "C"}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("title order = %v, want %v", titles, want)
	}
}

// TestDeduplicate_EmptyAndSingle: defensive cases — must not panic on
// empty input or wrap a single finding into a noisier shape.
func TestDeduplicate_EmptyAndSingle(t *testing.T) {
	if got := Deduplicate(nil); len(got) != 0 {
		t.Errorf("nil input: want 0 findings, got %d", len(got))
	}
	if got := Deduplicate([]models.Finding{}); len(got) != 0 {
		t.Errorf("empty input: want 0 findings, got %d", len(got))
	}
	one := []models.Finding{{Title: "X", Category: "c", Severity: models.SeverityHigh, Endpoint: "/1"}}
	out := Deduplicate(one)
	if len(out) != 1 {
		t.Fatalf("single input: want 1 out, got %d", len(out))
	}
	if out[0].AffectedEndpoints != nil {
		t.Errorf("single input must not set AffectedEndpoints")
	}
}
