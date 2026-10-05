package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// These tests lock the SECURITY INVARIANT of SARIF import:
//
//	An imported finding may strengthen a fendix decision, but it can only
//	satisfy the "both engines confirm" gate when INDEPENDENT engines report
//	the same normalized weakness at the same sufficiently precise location.
//
// Title similarity, category equality, fingerprint collisions, same-file
// proximity, an imported tool's self-declared confidence, and the same
// external tool duplicated across runs must all fail to correlate strongly.

func lineptr(s string) *string { return &s }

func nativeSQLi(endpoint, line string) evidence.Evidence {
	return evidence.Evidence{
		Title:      "SQL injection via string-formatted query",
		Category:   "injection",
		Endpoint:   endpoint,
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceMedium,
		References: []string{"CWE-89"},
		Line:       lineptr(line),
	}
}

func importedSQLi(tool, endpoint, line string) evidence.Evidence {
	return evidence.Evidence{
		Title:      "SQL Injection",
		Category:   "injection",
		Endpoint:   endpoint,
		Severity:   models.SeverityHigh,
		Source:     models.SourceImported,
		Confidence: models.ConfidenceMedium,
		Weakness:   []string{"CWE-89"},
		ToolID:     tool,
		References: []string{"CWE-89", "tool:" + tool, "rule:sql-injection"},
		Line:       lineptr(line),
	}
}

// ── The strong predicate itself ─────────────────────────────────────────────

func TestStrongCorroboration_IndependentToolsSameCWENearLocation(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:102", "102")

	if got := ClassifyCrossTool(native, imported); got != MatchStrong {
		t.Fatalf("native CWE-89 @views.py:100 vs codeql CWE-89 @views.py:102 = %v, want MatchStrong", got)
	}
}

func TestNoStrongCorroboration_FarAwayLocation(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:400", "400")

	got := ClassifyCrossTool(native, imported)
	if got == MatchStrong {
		t.Fatal("same CWE + same file but 300 lines apart must NOT correlate strongly")
	}
	if got != MatchMedium {
		t.Fatalf("same weakness + same file outside the threshold should classify medium, got %v", got)
	}
}

func TestNoStrongCorroboration_FromTitleAlone(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:101", "101")
	imported.Title = native.Title          // identical title...
	imported.Weakness = []string{"CWE-79"} // ...but a DIFFERENT weakness

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("identical titles with different CWEs in the same file must NOT correlate strongly")
	}
}

func TestNoStrongCorroboration_FromCategoryAlone(t *testing.T) {
	native := nativeSQLi("app/db.py:10", "10")
	imported := importedSQLi("codeql", "app/api.py:200", "200")
	imported.Weakness = nil // unknown CWE; categories still both "injection"

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("category equality with unknown CWE and different locations must NOT correlate strongly")
	}
}

func TestNoStrongCorroboration_UnknownCWE(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:100", "100")
	imported.Weakness = nil // same file, same line, similar title — but no CWE

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("an import with no recognizable CWE must NOT strongly corroborate, whatever else matches")
	}
}

func TestNoStrongCorroboration_MissingLocation(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "unknown", "")
	imported.Line = nil

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("an import with no usable location must NOT participate in strong corroboration")
	}
}

func TestNoIndependence_SameExternalTool(t *testing.T) {
	a := importedSQLi("codeql", "app/views.py:100", "100")
	b := importedSQLi("codeql", "app/views.py:101", "101")

	if got := ClassifyCrossTool(a, b); got == MatchStrong {
		t.Fatal("the same external tool across two results/runs must NOT count as independent confirmation")
	}
}

func TestNoIndependence_FendixSemgrepShimVsImportedSemgrep(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	native.SourceTier = models.TierSemgrepShim // fendix's own semgrep pass
	imported := importedSQLi("semgrep", "app/views.py:101", "101")

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("fendix's semgrep shim and an imported semgrep SARIF are the same effective engine — not independent")
	}
}

func TestIndependence_TwoDifferentImportedTools(t *testing.T) {
	a := importedSQLi("codeql", "app/views.py:100", "100")
	b := importedSQLi("semgrep", "app/views.py:101", "101")

	if got := ClassifyCrossTool(a, b); got != MatchStrong {
		t.Fatalf("codeql + semgrep at the same weakness/location are independent, got %v", got)
	}
}

func TestStrongCorroboration_URLEndpoints(t *testing.T) {
	native := evidence.Evidence{
		Title: "SSRF via url parameter", Category: "ssrf",
		Endpoint: "GET /fetch", Severity: models.SeverityHigh,
		Source: models.SourceBlackbox, Confidence: models.ConfidenceMedium,
		References: []string{"CWE-918"},
	}
	imported := evidence.Evidence{
		Title: "Server-Side Request Forgery", Category: "ssrf",
		Endpoint: "https://api.example.com/fetch", Severity: models.SeverityHigh,
		Source: models.SourceImported, Confidence: models.ConfidenceMedium,
		Weakness: []string{"CWE-918"}, ToolID: "zap",
	}
	if got := ClassifyCrossTool(native, imported); got != MatchStrong {
		t.Fatalf("independent tools, same CWE, same normalized URL path = %v, want MatchStrong", got)
	}
}

// ── Threshold boundary ──────────────────────────────────────────────────────

func TestLineDistanceThresholdBoundary(t *testing.T) {
	cases := []struct {
		distance int
		want     MatchLevel
	}{
		{0, MatchStrong},
		{1, MatchStrong},
		{5, MatchStrong},
		{6, MatchMedium},
	}
	for _, tc := range cases {
		nLine := 100
		iLine := 100 + tc.distance
		native := nativeSQLi("app/views.py:100", "100")
		imported := importedSQLi("codeql", "app/views.py:"+itoa(iLine), itoa(iLine))
		_ = nLine
		if got := ClassifyCrossTool(native, imported); got != tc.want {
			t.Errorf("line distance %d: got %v, want %v", tc.distance, got, tc.want)
		}
	}
}

func TestOverlappingRegionsBeatRawDistance(t *testing.T) {
	// 6 lines apart — beyond the proximity threshold — but both sides carry
	// ranges and the ranges overlap: the exact-region agreement decides.
	a := importedSQLi("codeql", "app/views.py:100", "100")
	a.LineEnd = 110
	b := importedSQLi("semgrep", "app/views.py:106", "106")
	b.LineEnd = 107
	if got := ClassifyCrossTool(a, b); got != MatchStrong {
		t.Fatalf("overlapping regions must establish location agreement, got %v", got)
	}

	// Both ranged, near by raw distance, but the ranges do NOT overlap:
	// ranges are authoritative when both sides declare them.
	c := importedSQLi("codeql", "app/views.py:100", "100")
	c.LineEnd = 101
	d := importedSQLi("semgrep", "app/views.py:104", "104")
	d.LineEnd = 105
	if got := ClassifyCrossTool(c, d); got == MatchStrong {
		t.Fatal("non-overlapping declared regions must not correlate strongly, even within the raw distance")
	}
}

// ── CorrelateCrossTool: stamping + representative selection ─────────────────

func TestNativeRemainsRepresentative_ImportedProvenanceRetained(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:102", "102")

	out, _ := CorrelateCrossTool([]evidence.Evidence{native, imported})
	if len(out) != 1 {
		t.Fatalf("strong native+imported match must collapse to one representative, got %d rows", len(out))
	}
	rep := out[0]
	if rep.Source != models.SourceWhitebox {
		t.Fatalf("the NATIVE finding must remain the representative, got source %q", rep.Source)
	}
	if !rep.CrossToolCorroborated {
		t.Fatal("the representative must carry the corroboration stamp")
	}
	if len(rep.CorroboratingTools) != 1 || rep.CorroboratingTools[0] != "codeql" {
		t.Fatalf("CorroboratingTools = %v, want [codeql]", rep.CorroboratingTools)
	}
	if !containsRef(rep.References, "rule:sql-injection") {
		t.Fatalf("imported provenance must survive on the representative, refs = %v", rep.References)
	}
	// The representative's own trust surface must not change.
	if rep.Confidence != models.ConfidenceMedium || rep.Severity != models.SeverityHigh {
		t.Fatalf("corroboration must not rewrite the native confidence/severity: %v/%v", rep.Confidence, rep.Severity)
	}
	if rep.Source == models.SourceCorrelated || rep.Reachable || rep.ProvenPath {
		t.Fatal("cross-tool corroboration must not mint correlated/reachable/proven-path status")
	}
}

func TestSameToolDuplicates_KeptButNeverStamped(t *testing.T) {
	a := importedSQLi("codeql", "app/views.py:100", "100")
	b := importedSQLi("codeql", "app/views.py:101", "101")

	out, _ := CorrelateCrossTool([]evidence.Evidence{a, b})
	if len(out) != 2 {
		t.Fatalf("same-tool duplicates are dedup's business, not correlation's — got %d rows", len(out))
	}
	for _, ev := range out {
		if ev.CrossToolCorroborated {
			t.Fatal("duplication of one tool must not manufacture independent confirmation")
		}
	}
}

func TestImportedPairFromDifferentTools_BothKeptBothStamped(t *testing.T) {
	a := importedSQLi("codeql", "app/views.py:100", "100")
	b := importedSQLi("semgrep", "app/views.py:101", "101")

	out, _ := CorrelateCrossTool([]evidence.Evidence{a, b})
	if len(out) != 2 {
		t.Fatalf("imported↔imported strong pairs keep both rows, got %d", len(out))
	}
	for _, ev := range out {
		if !ev.CrossToolCorroborated {
			t.Fatalf("both sides of an independent imported pair must be stamped: %+v", ev.ToolID)
		}
	}
}

// TestCorrelateCrossTool_ReturnsPerToolCollapsedCounts: the counts must be
// keyed by tool. A scalar total cannot be attributed when two tools each
// collapse findings — which block of metadata.imports would it belong to?
func TestCorrelateCrossTool_ReturnsPerToolCollapsedCounts(t *testing.T) {
	evs := []evidence.Evidence{
		nativeSQLi("app/views.py:100", "100"),
		nativeSQLi("app/db.py:200", "200"),
		nativeSQLi("app/api.py:300", "300"),
		importedSQLi("codeql", "app/views.py:102", "102"),
		importedSQLi("codeql", "app/db.py:201", "201"),
		importedSQLi("semgrep", "app/api.py:301", "301"),
	}
	_, counts := CorrelateCrossTool(evs)
	if counts["codeql"] != 2 {
		t.Fatalf("codeql collapsed count = %d, want 2", counts["codeql"])
	}
	if counts["semgrep"] != 1 {
		t.Fatalf("semgrep collapsed count = %d, want 1", counts["semgrep"])
	}
}

func TestCorrelateCrossTool_NoImportsReturnsNilCounts(t *testing.T) {
	_, counts := CorrelateCrossTool([]evidence.Evidence{nativeSQLi("app/views.py:100", "100")})
	if len(counts) != 0 {
		t.Fatalf("no imports → no counts, got %v", counts)
	}
}

func TestCorrelateCrossTool_NoImports_NoOp(t *testing.T) {
	evs := []evidence.Evidence{nativeSQLi("app/views.py:100", "100"), nativeSQLi("app/db.py:5", "5")}
	out, _ := CorrelateCrossTool(evs)
	if len(out) != 2 {
		t.Fatalf("no imports → untouched, got %d rows", len(out))
	}
	for _, ev := range out {
		if ev.CrossToolCorroborated {
			t.Fatal("native↔native agreement is out of scope for cross-tool correlation")
		}
	}
}

// ── Fences: legacy correlator and dedup ─────────────────────────────────────

func TestImportedFencedOutOfBlackboxWhiteboxCorrelator(t *testing.T) {
	wb := nativeSQLi("app/views.py:100", "100")
	imp := importedSQLi("codeql", "/views", "0")
	imp.Endpoint = "/views" // URL-shaped, category-related — the old default arm would have fuzzy-matched it

	out := Correlate([]models.Finding{wb.ToFinding(), imp.ToFinding()})
	if len(out) != 2 {
		t.Fatalf("imported findings must pass through the BB↔WB correlator untouched, got %d rows", len(out))
	}
	for _, f := range out {
		if f.Source == models.SourceCorrelated {
			t.Fatal("an imported finding must never mint a Source=correlated merge")
		}
	}
}

func TestDedup_ImportedTitleCollisionCannotTransferConfidence(t *testing.T) {
	native := models.Finding{
		Title: "SQL Injection", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceMedium,
		Endpoint: "app/views.py:100",
	}
	imported := models.Finding{
		Title: "SQL Injection", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceImported, Confidence: models.ConfidenceHigh, // tool's self-claim
		Endpoint: "somewhere/else.py:1",
	}
	out := Deduplicate([]models.Finding{native, imported})
	if len(out) != 2 {
		t.Fatalf("a title/category collision must NOT merge an imported finding into a native group (got %d rows)", len(out))
	}
	for _, f := range out {
		if f.Source == models.SourceWhitebox && f.Confidence != models.ConfidenceMedium {
			t.Fatal("the imported tool's self-declared HIGH confidence leaked onto the native finding")
		}
	}
}

// ── End-to-end: the gate ────────────────────────────────────────────────────

// TestGate_CorroboratedImportBlocks_UncorroboratedWarns drives the decision
// layer with the exact evidence shapes CorrelateCrossTool produces, proving
// strong corroboration — and only strong corroboration — lifts a MEDIUM-band
// imported finding over the --fail-on gate.
func TestGate_CorroboratedImportBlocks_UncorroboratedWarns(t *testing.T) {
	opts := decision.Options{EnforceConfidence: true}

	uncorroborated := importedSQLi("codeql", "app/views.py:102", "102")
	d := decision.DecideWithOptions(uncorroborated, "HIGH", opts)
	if d.Status != decision.StatusWarn {
		t.Fatalf("an uncorroborated MEDIUM-precision import above --fail-on must WARN, got %v (%s)", d.Status, d.Reason)
	}

	out, _ := CorrelateCrossTool([]evidence.Evidence{
		nativeSQLi("app/views.py:100", "100"),
		importedSQLi("codeql", "app/views.py:102", "102"),
	})
	if len(out) != 1 || !out[0].CrossToolCorroborated {
		t.Fatalf("precondition: expected one corroborated representative, got %+v", out)
	}
	d = decision.DecideWithOptions(out[0], "HIGH", opts)
	if d.Status != decision.StatusBlock {
		t.Fatalf("a strongly corroborated finding above --fail-on must BLOCK, got %v (%s)", d.Status, d.Reason)
	}
	if !strings.Contains(d.Reason, "independent cross-tool corroboration") {
		t.Fatalf("the BLOCK reason must name the cross-tool signal, got %q", d.Reason)
	}
}

// TestGate_WeakSimilaritySignalsNothing pins requirement 6: same file, same
// category, similar titles — no strong match, no corroboration signal, no
// BLOCK.
func TestGate_WeakSimilaritySignalsNothing(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	imported := importedSQLi("codeql", "app/views.py:400", "400") // same weakness, far away

	out, _ := CorrelateCrossTool([]evidence.Evidence{native, imported})
	if len(out) != 2 {
		t.Fatalf("a non-strong pair must not collapse, got %d rows", len(out))
	}
	for _, ev := range out {
		if ev.CrossToolCorroborated {
			t.Fatal("medium/weak similarity must not stamp corroboration")
		}
		d := decision.DecideWithOptions(ev, "HIGH", decision.Options{EnforceConfidence: true})
		if d.Status == decision.StatusBlock {
			t.Fatalf("nothing in this pair may BLOCK (both MEDIUM band, uncorroborated), got %v for %s", d.Status, ev.ToolID)
		}
	}
}

func containsRef(refs []string, want string) bool {
	for _, r := range refs {
		if r == want {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
