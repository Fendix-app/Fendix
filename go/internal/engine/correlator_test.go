package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func linePtr(s string) *string { return &s }

func TestCorrelate_MatchingFindings(t *testing.T) {
	bb := models.Finding{
		Title:      "Missing authentication",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/users",
		Evidence:   "200 OK without auth",
		Fix:        "Add authentication",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth decorator",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "routes/users.py:42",
		Evidence:   "No @login_required",
		Fix:        "Add @login_required",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
		Line:       linePtr("routes/users.py:42"),
	}

	result := Correlate([]models.Finding{bb, wb})

	// Should produce 1 correlated finding
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", f.Source)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected confidence HIGH, got %s", f.Confidence)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL (escalated from CRITICAL stays CRITICAL), got %s", f.Severity)
	}
	if f.Line == nil {
		t.Error("expected line from whitebox finding to be preserved")
	}
}

// TASK-092: a file:line whitebox finding cannot be confirmed by a live HTTP
// scan, so the [Unconfirmed by live scan] suffix is misleading there. The
// finding should pass through unchanged (confidence, evidence, source).
func TestCorrelate_FilePathWhiteboxNotMarkedUnconfirmed(t *testing.T) {
	wb := models.Finding{
		Title:      "SQL injection pattern",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "injection",
		Endpoint:   "db/queries.py:15",
		Evidence:   "cursor.execute(f\"SELECT...\")",
		Fix:        "Use parameterized queries",
		References: []string{"CWE-89"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceWhitebox {
		t.Errorf("expected source whitebox, got %s", f.Source)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected confidence HIGH (file:line endpoint, no live-scan confirmation possible), got %s", f.Confidence)
	}
	if f.Evidence != "cursor.execute(f\"SELECT...\")" {
		t.Errorf("expected unchanged evidence, got %q", f.Evidence)
	}
}

// TASK-092: a URL-endpoint whitebox finding with no matching blackbox finding
// (live scan ran clean for that endpoint) still gets the suffix and confidence
// downgrade — that's the case the suffix is designed for.
func TestCorrelate_URLWhiteboxMarkedUnconfirmed(t *testing.T) {
	wb := models.Finding{
		Title:      "Endpoint missing security",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "GET /api/v1/admin",
		Evidence:   "No security defined in spec",
		Fix:        "Add a security requirement",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Confidence != models.ConfidenceMedium {
		t.Errorf("expected confidence MEDIUM (URL endpoint, downgraded), got %s", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "[Unconfirmed by live scan]") {
		t.Errorf("expected unconfirmed suffix on URL-endpoint finding, got %q", f.Evidence)
	}
}

func TestCorrelate_BlackboxOnly(t *testing.T) {
	bb := models.Finding{
		Title:      "Missing HSTS header",
		Severity:   models.SeverityMedium,
		Source:     models.SourceBlackbox,
		Category:   "headers",
		Endpoint:   "http://example.com/api/users",
		Evidence:   "HSTS header not present",
		Fix:        "Add HSTS header",
		References: []string{"CWE-319"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{bb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected source blackbox (unchanged), got %s", f.Source)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected severity MEDIUM (unchanged), got %s", f.Severity)
	}
}

func TestCorrelate_NoFindings(t *testing.T) {
	result := Correlate(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestCorrelate_MixedWithUncorrelated(t *testing.T) {
	findings := []models.Finding{
		{
			Title:      "Missing HSTS",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "headers",
			Endpoint:   "http://example.com/api/v1/users",
			Evidence:   "No HSTS header",
			Fix:        "Add HSTS",
			References: []string{},
			Confidence: models.ConfidenceHigh,
		},
		{
			Title:      "Hardcoded secret",
			Severity:   models.SeverityHigh,
			Source:     models.SourceWhitebox,
			Category:   "secrets",
			Endpoint:   "config/settings.py:8",
			Evidence:   "API_KEY = 'sk-...'",
			Fix:        "Use env var",
			References: []string{"CWE-798"},
			Confidence: models.ConfidenceHigh,
		},
		{
			Title:      "Password in response",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "data_exposure",
			Endpoint:   "http://example.com/api/v1/users",
			Evidence:   "password field in JSON",
			Fix:        "Remove sensitive fields",
			References: []string{"CWE-200"},
			Confidence: models.ConfidenceHigh,
		},
	}

	result := Correlate(findings)

	// "Hardcoded secret" (whitebox, secrets) should NOT correlate with blackbox "headers"
	// but should try to correlate with "data_exposure" on /users — endpoint segments differ
	// so it stays unconfirmed.
	// Total: 3 findings (no correlation expected since endpoints don't match)
	hasBlackbox := false
	hasWhitebox := false
	for _, f := range result {
		if f.Source == models.SourceBlackbox {
			hasBlackbox = true
		}
		if f.Source == models.SourceWhitebox {
			hasWhitebox = true
		}
	}

	if !hasBlackbox {
		t.Error("expected blackbox findings to be present")
	}
	if !hasWhitebox {
		t.Error("expected whitebox finding to be present (unconfirmed)")
	}
}

func TestCorrelate_SeverityEscalation(t *testing.T) {
	// When correlated, severity escalates by one level
	bb := models.Finding{
		Title:      "No auth required",
		Severity:   models.SeverityHigh,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/admin",
		Evidence:   "200 without auth",
		Fix:        "Add auth",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth check",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "handlers/admin.py:10",
		Evidence:   "No auth decorator",
		Fix:        "Add decorator",
		References: []string{"CWE-862"},
		Confidence: models.ConfidenceHigh,
		Line:       linePtr("handlers/admin.py:10"),
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}

	// HIGH escalated = CRITICAL
	if result[0].Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL (escalated from HIGH), got %s", result[0].Severity)
	}
}

func TestCorrelate_ReferencesMerged(t *testing.T) {
	bb := models.Finding{
		Title:      "Auth bypass",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/config",
		Evidence:   "200 no auth",
		Fix:        "Fix",
		References: []string{"CWE-306", "OWASP-A01"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "routes/config.py:5",
		Evidence:   "No decorator",
		Fix:        "Fix",
		References: []string{"CWE-306", "CWE-862"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	refs := result[0].References
	// Should have CWE-306, OWASP-A01, CWE-862 (deduplicated)
	if len(refs) != 3 {
		t.Errorf("expected 3 merged references, got %d: %v", len(refs), refs)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"full URL", "http://example.com/api/v1/users", "/api/v1/users"},
		{"URL with trailing slash", "http://example.com/api/v1/users/", "/api/v1/users"},
		{"URL with query", "http://example.com/api/v1/users?page=1", "/api/v1/users"},
		{"URL root", "http://example.com/", "/"},
		{"file path", "src/config.py:14", "src/config.py"},
		{"file path no line", "routes/users.py", "routes/users.py"},
		{"bare path", "/api/v1/users", "/api/v1/users"},
		{"empty", "", ""},
		// TASK-091: spec-parser endpoints have a "<METHOD> <PATH>" prefix.
		{"method prefix GET", "GET /pet/findByStatus", "/pet/findbystatus"},
		{"method prefix POST", "POST /users", "/users"},
		{"method prefix lowercase", "delete /api/v1/items/42", "/api/v1/items/42"},
		{"method prefix with full URL", "GET http://example.com/pet", "/pet"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEndpoint(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestEndpointsRelated(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"exact match", "/api/v1/users", "/api/v1/users", true},
		{"path vs file", "/api/v1/users", "routes/users.py", true},
		{"path vs handler", "/api/v1/admin", "handlers/admin.py", true},
		{"unrelated", "/api/v1/users", "config/settings.py", false},
		{"short segments ignored", "/a", "/a", true}, // exact match
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointsRelated(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("endpointsRelated(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestEscalateSeverity(t *testing.T) {
	tests := []struct {
		input    models.Severity
		expected models.Severity
	}{
		{models.SeverityInfo, models.SeverityLow},
		{models.SeverityLow, models.SeverityMedium},
		{models.SeverityMedium, models.SeverityHigh},
		{models.SeverityHigh, models.SeverityCritical},
		{models.SeverityCritical, models.SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(string(tc.input), func(t *testing.T) {
			got := escalateSeverity(tc.input)
			if got != tc.expected {
				t.Errorf("escalateSeverity(%s) = %s, want %s", tc.input, got, tc.expected)
			}
		})
	}
}

func TestHigherSeverity(t *testing.T) {
	tests := []struct {
		a, b     models.Severity
		expected models.Severity
	}{
		{models.SeverityHigh, models.SeverityMedium, models.SeverityHigh},
		{models.SeverityMedium, models.SeverityCritical, models.SeverityCritical},
		{models.SeverityLow, models.SeverityLow, models.SeverityLow},
	}

	for _, tc := range tests {
		t.Run(string(tc.a)+"_vs_"+string(tc.b), func(t *testing.T) {
			got := higherSeverity(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("higherSeverity(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestMergeRefs(t *testing.T) {
	a := []string{"CWE-306", "OWASP-A01"}
	b := []string{"CWE-306", "CWE-862"}

	result := mergeRefs(a, b)
	if len(result) != 3 {
		t.Errorf("expected 3 refs, got %d: %v", len(result), result)
	}

	expected := map[string]bool{"CWE-306": true, "OWASP-A01": true, "CWE-862": true}
	for _, r := range result {
		if !expected[r] {
			t.Errorf("unexpected ref: %s", r)
		}
	}
}

// TASK-091: Real-world petstore3 case — whitebox spec parser emits endpoint
// "GET /pet/findByStatus", blackbox emits the full URL with the server's
// /api/v3 base path. The pre-fix correlator returned 0 correlated findings
// here. Now must merge via path-suffix match.
func TestCorrelate_PathSuffixMatch_PetstoreStyle(t *testing.T) {
	bb := models.Finding{
		Title:      "No auth required",
		Severity:   models.SeverityHigh,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "https://petstore3.swagger.io/api/v3/pet/findByStatus",
		Evidence:   "200 without auth",
		Fix:        "Add auth",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Endpoint has no authentication requirement",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "GET /pet/findByStatus",
		Evidence:   "GET /pet/findByStatus has no security defined.",
		Fix:        "Add a security requirement.",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceMedium,
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding (suffix match), got %d", len(result))
	}
	if result[0].Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", result[0].Source)
	}
}

// TASK-091: blackbox path /api/v1/users contains whitebox path /users on a
// `/` boundary. Suffix match should fire even when there's no method prefix
// in the whitebox finding.
func TestCorrelate_PathSuffixMatch_BarePath(t *testing.T) {
	bb := models.Finding{
		Title:    "Sensitive data exposed",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "data_exposure",
		Endpoint: "http://example.com/api/v1/users",
	}

	wb := models.Finding{
		Title:    "Hardcoded API key",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "secrets",
		Endpoint: "/users",
		Evidence: "API_KEY = 'sk-...'",
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding via suffix, got %d", len(result))
	}
	if result[0].Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", result[0].Source)
	}
}

// TASK-091: each blackbox finding can correlate with at most one whitebox
// finding. Without the `taken` set, two different whitebox findings could
// both merge with the same blackbox.
func TestCorrelate_BlackboxConsumedAtMostOnce(t *testing.T) {
	bb := models.Finding{
		Title:    "No auth required",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "auth_bypass",
		Endpoint: "http://example.com/api/v1/users",
	}

	wb1 := models.Finding{
		Title:    "Missing auth decorator",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "auth",
		Endpoint: "GET /users",
	}

	wb2 := models.Finding{
		Title:    "Different auth bug",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "auth",
		Endpoint: "POST /users",
	}

	result := Correlate([]models.Finding{bb, wb1, wb2})

	correlatedCount := 0
	unconfirmedCount := 0
	for _, f := range result {
		if f.Source == models.SourceCorrelated {
			correlatedCount++
		}
		if f.Source == models.SourceWhitebox {
			unconfirmedCount++
		}
	}

	if correlatedCount != 1 {
		t.Errorf("expected exactly 1 correlated finding (blackbox consumed once), got %d", correlatedCount)
	}
	if unconfirmedCount != 1 {
		t.Errorf("expected 1 unconfirmed whitebox (the second wf had no available bb), got %d", unconfirmedCount)
	}
}

func TestPathSuffixMatch(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"exact match", "/api/v1/users", "/api/v1/users", true},
		{"suffix match", "/users", "/api/v1/users", true},
		{"suffix match reversed args", "/api/v1/users", "/users", true},
		{"deeper suffix", "/pet/findbystatus", "/api/v3/pet/findbystatus", true},
		{"mid-segment boundary rejected", "/3/pet", "/api/v3/pet", false},
		{"trivial root rejected", "/", "/api/v1/users", false},
		{"non-path inputs rejected", "src/config.py", "/api/v1/users", false},
		{"no shared suffix", "/items", "/api/v1/users", false},
		{"empty inputs rejected", "", "/users", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pathSuffixMatch(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("pathSuffixMatch(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

// TASK-114: when the whitebox half carries a TaintChain proving a
// dataflow source→sink, the merged correlated finding inherits the
// chain plus Reachable=true and gets a *second* severity escalation.
func TestCorrelate_ReachableWhiteboxEscalatesSeverityAndPropagatesChain(t *testing.T) {
	bb := models.Finding{
		Title:      "SQL Injection (boolean-based)",
		Severity:   models.SeverityMedium, // baseline MEDIUM blackbox
		Source:     models.SourceBlackbox,
		Category:   "injection",
		Endpoint:   "https://api.example.com/api/v1/users",
		Evidence:   "boolean payload toggled response",
		Confidence: models.ConfidenceHigh,
	}
	chain := []models.TaintLink{
		{File: "src/handlers.py", Line: 12, Expr: "request.args.get('id')"},
		{File: "src/handlers.py", Line: 14, Expr: "cursor.execute(query)"},
	}
	wb := models.Finding{
		Title:    "SQL query built via string formatting — injection risk",
		Severity: models.SeverityCritical, // CRITICAL whitebox
		Source:   models.SourceWhitebox,
		Category: "injection",
		// URL form (what spec_parser produces). The AST analyzer emits
		// file:line endpoints; in a real hybrid scan the spec_parser
		// finding correlates with blackbox and the AST chain is shared
		// via dedup-then-merge. For this unit test we exercise the
		// merge path directly.
		Endpoint:   "GET /api/v1/users",
		Evidence:   "cursor.execute(query)",
		Confidence: models.ConfidenceHigh,
		TaintChain: chain,
		Reachable:  true,
	}

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	got := result[0]
	if got.Source != models.SourceCorrelated {
		t.Errorf("source: want correlated, got %s", got.Source)
	}
	if !got.Reachable {
		t.Errorf("expected Reachable=true to propagate, got false")
	}
	if len(got.TaintChain) != len(chain) {
		t.Errorf("expected chain to propagate (%d links), got %d", len(chain), len(got.TaintChain))
	}
	// Without reachability: higher of (MEDIUM, CRITICAL) = CRITICAL,
	// then escalate once = CRITICAL (saturates). With reachability: a
	// second escalateSeverity call is a no-op at CRITICAL — but the
	// Reachable flag itself is the gate the reporter uses. Verify the
	// severity at minimum did not regress.
	if models.SeverityRank(got.Severity) < models.SeverityRank(models.SeverityHigh) {
		t.Errorf("severity should be at least HIGH for reachable correlated, got %s", got.Severity)
	}
}

// Below-CRITICAL severities exercise the second escalation path; verify
// MEDIUM blackbox + MEDIUM whitebox + Reachable jumps to CRITICAL.
func TestCorrelate_ReachableLowerSeverityDoubleEscalates(t *testing.T) {
	bb := models.Finding{
		Title:      "Open redirect",
		Severity:   models.SeverityMedium,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "https://api.example.com/redirect",
		Confidence: models.ConfidenceMedium,
	}
	wb := models.Finding{
		Title:      "Open redirect — user-controlled redirect target",
		Severity:   models.SeverityMedium,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "/redirect",
		Confidence: models.ConfidenceMedium,
		TaintChain: []models.TaintLink{
			{File: "h.py", Line: 3, Expr: "request.args.get('next')"},
			{File: "h.py", Line: 4, Expr: "redirect(target)"},
		},
		Reachable: true,
	}

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	// MEDIUM higher = MEDIUM → escalate = HIGH → reachability escalate = CRITICAL.
	if result[0].Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL for double-escalated reachable, got %s", result[0].Severity)
	}
	if !result[0].Reachable {
		t.Errorf("expected Reachable=true to propagate")
	}
}

// Without Reachable, correlation should NOT add the second escalation.
func TestCorrelate_NonReachableSingleEscalation(t *testing.T) {
	bb := models.Finding{
		Title:      "Missing CSP",
		Severity:   models.SeverityMedium,
		Source:     models.SourceBlackbox,
		Category:   "headers",
		Endpoint:   "https://api.example.com/health",
		Confidence: models.ConfidenceMedium,
	}
	wb := models.Finding{
		Title:      "Header policy missing",
		Severity:   models.SeverityMedium,
		Source:     models.SourceWhitebox,
		Category:   "headers",
		Endpoint:   "/health",
		Confidence: models.ConfidenceMedium,
		// No TaintChain, no Reachable.
	}

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	// MEDIUM → escalate once → HIGH (no second hop).
	if result[0].Severity != models.SeverityHigh {
		t.Errorf("expected single-escalation HIGH, got %s", result[0].Severity)
	}
	if result[0].Reachable {
		t.Errorf("Reachable should remain false when whitebox didn't carry a chain")
	}
}

func TestRelatedCategories(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"auth", "auth_bypass"},
		{"secrets", "data_exposure"},
		{"injection", "injection"},
		{"auth_bypass", "auth"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			cats := relatedCategories(tc.input)
			found := false
			for _, c := range cats {
				if c == tc.contains {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("relatedCategories(%q) should contain %q, got %v", tc.input, tc.contains, cats)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Proven Path v1 — route-pattern match (GAP 1)
//
// These exercise the highest-priority correlation strategy: when a whitebox
// finding carries a Route (populated by the Python route extractor) whose
// Pattern matches a blackbox endpoint segment-for-segment, the merged finding
// is RouteConfirmed. When the whitebox half is also Reachable, it becomes a
// ProvenPath CRITICAL.
//
// Note: the Finding struct has no Method field — a blackbox endpoint encodes
// its method as a "<METHOD> <path>" prefix (e.g. "GET /users/42"), which is
// how the correlator (and these tests) recover it for the method gate.
// ---------------------------------------------------------------------------

// routeWB builds a reachable whitebox finding bound to the given route. The
// tree_sitter tier is the high-trust tier that clears the F1 gate, so Proven
// Path escalation is allowed.
func routeWB(category string, route *models.Route, reachable bool) models.Finding {
	wb := models.Finding{
		Title:      "SQL injection in handler",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   category,
		Endpoint:   "app/views.py:42",
		Evidence:   "cursor.execute(f\"...{request.GET['id']}\")",
		Fix:        "Use parameterized queries",
		References: []string{"CWE-89"},
		Confidence: models.ConfidenceHigh,
		Line:       linePtr("app/views.py:42"),
		SourceTier: models.TierTreeSitter,
		Route:      route,
	}
	if reachable {
		wb.Reachable = true
		wb.TaintChain = []models.TaintLink{{File: "app/views.py", Line: 42, Expr: "request.GET['id']"}}
	}
	return wb
}

// routeBB builds a blackbox finding at a concrete endpoint. `endpoint` should
// include the method prefix when the test exercises the method gate, e.g.
// "GET /users/42".
func routeBB(category, endpoint string) models.Finding {
	return models.Finding{
		Title:      "Injection confirmed by live scan",
		Severity:   models.SeverityMedium,
		Source:     models.SourceBlackbox,
		Category:   category,
		Endpoint:   endpoint,
		Evidence:   "500 on payload",
		Fix:        "Sanitize input",
		References: []string{"CWE-89"},
		Confidence: models.ConfidenceHigh,
	}
}

func TestRoutePatternMatch_DjangoStyle(t *testing.T) {
	wb := routeWB("injection", &models.Route{
		Method:  "GET",
		Pattern: "/users/<int:pk>/",
		Handler: "views.get_user",
	}, false)
	bb := routeBB("injection", "GET /users/42/")

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	f := result[0]
	if f.Source != models.SourceCorrelated {
		t.Fatalf("expected correlated source, got %s", f.Source)
	}
	if !f.RouteConfirmed {
		t.Errorf("expected RouteConfirmed=true for Django route /users/<int:pk>/ vs /users/42/")
	}
	if f.Route == nil || f.Route.Pattern != "/users/<int:pk>/" {
		t.Errorf("expected Route to be preserved, got %+v", f.Route)
	}
}

func TestRoutePatternMatch_FastAPIStyle(t *testing.T) {
	wb := routeWB("injection", &models.Route{
		Pattern: "/items/{item_id}", // no method declared
		Handler: "read_item",
	}, false)
	bb := routeBB("injection", "/items/99") // no method prefix

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	if !result[0].RouteConfirmed {
		t.Errorf("expected RouteConfirmed=true for FastAPI route /items/{item_id} vs /items/99")
	}
}

func TestRoutePatternMatch_Express(t *testing.T) {
	wb := routeWB("injection", &models.Route{
		Pattern: "/users/:id", // Express-style param, no method declared
		Handler: "getUser",
	}, false)
	bb := routeBB("injection", "/users/7")

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	if !result[0].RouteConfirmed {
		t.Errorf("expected RouteConfirmed=true for Express route /users/:id vs /users/7")
	}
}

func TestRoutePatternMatch_MethodMismatch(t *testing.T) {
	wb := routeWB("injection", &models.Route{
		Method:  "POST",
		Pattern: "/users/{id}",
		Handler: "create_user",
	}, false)
	bb := routeBB("injection", "GET /users/42") // method GET != route POST

	result := Correlate([]models.Finding{bb, wb})

	// The route match is blocked by the method gate. The findings may still
	// correlate via a fallback strategy (fuzzy "users" segment), but they must
	// NOT be route-confirmed.
	for _, f := range result {
		if f.RouteConfirmed {
			t.Errorf("expected RouteConfirmed=false on method mismatch (POST route vs GET endpoint), got true on %q", f.Title)
		}
		if f.ProvenPath {
			t.Errorf("method mismatch must never yield ProvenPath, got true on %q", f.Title)
		}
	}
}

func TestRoutePatternMatch_NilRoute(t *testing.T) {
	// wf.Route == nil — the route block must be skipped silently and the
	// existing exact/suffix/fuzzy strategies must still run (and here, match
	// on the shared path), with no panic and RouteConfirmed=false.
	wb := models.Finding{
		Title:      "Missing auth",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "/api/v1/users",
		Evidence:   "no @login_required",
		Confidence: models.ConfidenceHigh,
		Route:      nil, // explicit
	}
	bb := models.Finding{
		Title:      "Auth bypass confirmed",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/users",
		Evidence:   "200 without auth",
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected existing strategies to still correlate (1 finding), got %d", len(result))
	}
	if result[0].RouteConfirmed {
		t.Errorf("nil Route must yield RouteConfirmed=false")
	}
	if result[0].ProvenPath {
		t.Errorf("nil Route must yield ProvenPath=false")
	}
}

func TestProvenPathEscalation(t *testing.T) {
	// RouteConfirmed (route pattern match) + Reachable (taint chain) →
	// forced CRITICAL + ProvenPath=true, even though the base severities are
	// well below CRITICAL (whitebox HIGH, blackbox MEDIUM).
	wb := routeWB("injection", &models.Route{
		Method:  "GET",
		Pattern: "/users/{id}",
		Handler: "get_user",
	}, true) // reachable
	bb := routeBB("injection", "GET /users/42")

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	f := result[0]
	if !f.RouteConfirmed {
		t.Fatalf("precondition: expected RouteConfirmed=true")
	}
	if !f.ProvenPath {
		t.Errorf("expected ProvenPath=true when RouteConfirmed && Reachable")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected Proven Path to force CRITICAL, got %s", f.Severity)
	}
}

// TestProvenPath_NotSetFromRouteConfirmedAlone guards the rule: ProvenPath must
// require BOTH route_confirmed AND reachable — a route match on a NON-reachable
// finding must not flip ProvenPath. Severities are kept low (both LOW) so the
// ordinary single correlation-escalation (LOW→MEDIUM) lands below CRITICAL,
// isolating the Proven Path forced-CRITICAL effect: without reachability the
// finding must NOT be forced to CRITICAL.
func TestProvenPath_NotSetFromRouteConfirmedAlone(t *testing.T) {
	wb := routeWB("injection", &models.Route{
		Method:  "GET",
		Pattern: "/users/{id}",
		Handler: "get_user",
	}, false) // NOT reachable
	wb.Severity = models.SeverityLow
	bb := routeBB("injection", "GET /users/42")
	bb.Severity = models.SeverityLow

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}
	f := result[0]
	if !f.RouteConfirmed {
		t.Fatalf("precondition: expected RouteConfirmed=true")
	}
	if f.ProvenPath {
		t.Errorf("ProvenPath must be false when not reachable, even with RouteConfirmed")
	}
	// LOW+LOW correlated escalates once to MEDIUM; without reachability there
	// is no second/forced bump, so it must stay below CRITICAL.
	if f.Severity == models.SeverityCritical {
		t.Errorf("non-reachable route-confirmed finding must not be forced to CRITICAL, got %s", f.Severity)
	}
}

// TestNormalizeRoutePattern covers the four framework dialects plus the
// trailing-slash / double-slash / leading-slash normalization rules.
func TestNormalizeRoutePattern(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/users/<int:pk>/", "/users/{}"},                      // Django typed
		{"/users/<id>", "/users/{}"},                           // Flask / Django untyped
		{"/items/{item_id}", "/items/{}"},                      // FastAPI
		{"/users/:id", "/users/{}"},                            // Express
		{"users/<int:id>", "/users/{}"},                        // missing leading slash
		{"/a//b/", "/a/b"},                                     // double slash collapse + trailing
		{"/orders/<int:oid>/items/{i}", "/orders/{}/items/{}"}, // mixed
		{"", ""},   // empty stays empty
		{"/", "/"}, // root
	}
	for _, c := range cases {
		if got := normalizeRoutePattern(c.in); got != c.want {
			t.Errorf("normalizeRoutePattern(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPathSegmentsMatch covers the wildcard-segment matcher's exactness:
// segment count must match and literals must match; {} matches one segment.
func TestPathSegmentsMatch(t *testing.T) {
	cases := []struct {
		pattern, endpoint string
		want              bool
	}{
		{"/users/{}", "/users/42", true},
		{"/users/{}", "/users/42/edit", false},     // segment count
		{"/users/{}/edit", "/users/42/edit", true}, // wildcard mid-path
		{"/users/{}", "/orders/42", false},         // literal mismatch
		{"/users/{}", "/api/v3/users/42", false},   // base-path skew NOT a route match
		{"/{}", "/anything", true},                 // single wildcard
	}
	for _, c := range cases {
		if got := pathSegmentsMatch(c.pattern, c.endpoint); got != c.want {
			t.Errorf("pathSegmentsMatch(%q, %q) = %v, want %v", c.pattern, c.endpoint, got, c.want)
		}
	}
}
