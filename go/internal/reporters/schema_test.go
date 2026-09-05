package reporters

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// validateAgainstSchema enforces the contract documented in docs/schema.md
// and mirrored in docs/schema.json. It is intentionally hand-rolled rather
// than driven by a JSON Schema library to avoid pulling in a third-party
// dependency for a single test file. If the schema doc and this validator
// drift apart, the doc is the source of truth.
func validateAgainstSchema(t *testing.T, report map[string]any) {
	t.Helper()

	requireKeys(t, "(root)", report, []string{"metadata", "summary", "sources", "total", "findings"})

	meta := requireObject(t, "metadata", report["metadata"])
	requireKeys(t, "metadata", meta, []string{"target", "started_at", "duration", "version", "mode", "endpoints_scanned", "active_probes"})
	requireString(t, "metadata.target", meta["target"])
	requireString(t, "metadata.started_at", meta["started_at"])
	requireString(t, "metadata.duration", meta["duration"])
	requireString(t, "metadata.version", meta["version"])
	requireEnum(t, "metadata.mode", meta["mode"], []string{"blackbox", "whitebox", "hybrid"})
	requireInt(t, "metadata.endpoints_scanned", meta["endpoints_scanned"])
	requireBool(t, "metadata.active_probes", meta["active_probes"])
	// schema_version is type-checked when present but not required: reports
	// written before the field existed omit it entirely and must still
	// validate. Same treatment docs/schema.json gives it — the key is in
	// `properties` (it has to be, `additionalProperties` is false) but not
	// in `required`.
	if sv, ok := meta["schema_version"]; ok {
		requireInt(t, "metadata.schema_version", sv)
	}
	if checks, ok := meta["checks_run"]; ok {
		arr := requireArray(t, "metadata.checks_run", checks)
		for i, c := range arr {
			requireString(t, "metadata.checks_run[]", c)
			_ = i
		}
	}
	if raw, ok := meta["scanner_status"]; ok {
		for i, item := range requireArray(t, "metadata.scanner_status", raw) {
			entry := requireObject(t, "metadata.scanner_status[]", item)
			path := "metadata.scanner_status[" + itoa(i) + "]"
			requireKeys(t, path, entry, []string{"name", "state"})
			state, _ := entry["state"].(string)
			requireEnum(t, path+".state", entry["state"], []string{"ok", "skipped", "failed"})
			reason, hasReason := entry["reason"].(string)
			switch state {
			case "ok":
				if hasReason {
					t.Errorf("%s: ok entry must not carry a reason, got %q", path, reason)
				}
			case "skipped":
				if !hasReason || !ScannerReason(reason).IsSkip() {
					t.Errorf("%s: skipped entry needs a skip reason, got %q", path, reason)
				}
			case "failed":
				if !hasReason || !ScannerReason(reason).IsFail() {
					t.Errorf("%s: failed entry needs a fail reason, got %q", path, reason)
				}
			}
			if a, ok := entry["attempts"]; ok {
				requireInt(t, path+".attempts", a)
			}
		}
	}
	if raw, ok := meta["coverage"]; ok {
		cov := requireObject(t, "metadata.coverage", raw)
		requireKeys(t, "metadata.coverage", cov, []string{"contract_version", "strict", "configured_complete", "gaps", "limitations", "required_analyzers", "required_gaps", "retried"})
		requireInt(t, "metadata.coverage.contract_version", cov["contract_version"])
		requireBool(t, "metadata.coverage.strict", cov["strict"])
		requireBool(t, "metadata.coverage.configured_complete", cov["configured_complete"])
		for _, k := range []string{"gaps", "limitations", "required_analyzers", "required_gaps", "retried"} {
			for _, v := range requireArray(t, "metadata.coverage."+k, cov[k]) {
				requireString(t, "metadata.coverage."+k+"[]", v)
			}
		}
	}
	if pv, ok := meta["policy_version"]; ok {
		requireString(t, "metadata.policy_version", pv)
	}

	sum := requireObject(t, "summary", report["summary"])
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		requireInt(t, "summary."+k, sum[k])
	}

	src := requireObject(t, "sources", report["sources"])
	for _, k := range []string{"blackbox", "whitebox", "correlated"} {
		requireInt(t, "sources."+k, src[k])
	}

	requireInt(t, "total", report["total"])

	findings := requireArray(t, "findings", report["findings"])
	for i, raw := range findings {
		f := requireObject(t, "findings[]", raw)
		path := "findings[" + itoa(i) + "]"
		requireKeys(t, path, f, []string{"id", "title", "severity", "source", "category", "endpoint", "evidence", "fix", "references", "confidence", "line"})

		requireString(t, path+".id", f["id"])
		if s, _ := f["id"].(string); !strings.HasPrefix(s, "SEC-") {
			t.Errorf("%s.id must start with SEC-, got %q", path, s)
		}
		requireString(t, path+".title", f["title"])
		sev := requireEnum(t, path+".severity", f["severity"], []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
		requireEnum(t, path+".source", f["source"], []string{"blackbox", "whitebox", "correlated"})
		requireString(t, path+".category", f["category"])
		requireString(t, path+".endpoint", f["endpoint"])
		if v, ok := f["affected_endpoints"]; ok {
			arr := requireArray(t, path+".affected_endpoints", v)
			for _, e := range arr {
				requireString(t, path+".affected_endpoints[]", e)
			}
		}
		requireString(t, path+".evidence", f["evidence"])
		requireString(t, path+".fix", f["fix"])
		requireArray(t, path+".references", f["references"])
		conf := requireEnum(t, path+".confidence", f["confidence"], []string{"HIGH", "MEDIUM", "LOW"})

		// `line` is required but may be null.
		if l, present := f["line"]; !present {
			t.Errorf("%s missing required field `line`", path)
		} else if l != nil {
			requireString(t, path+".line", l)
		}

		// taint_chain: optional; when present each link must have {file, line:int, expr}.
		if v, ok := f["taint_chain"]; ok {
			arr := requireArray(t, path+".taint_chain", v)
			for i, raw := range arr {
				link := requireObject(t, path+".taint_chain[]", raw)
				lp := path + ".taint_chain[" + itoa(i) + "]"
				requireKeys(t, lp, link, []string{"file", "line", "expr"})
				requireString(t, lp+".file", link["file"])
				requireInt(t, lp+".line", link["line"])
				requireString(t, lp+".expr", link["expr"])
			}
		}

		// reachable: optional boolean.
		if v, ok := f["reachable"]; ok {
			requireBool(t, path+".reachable", v)
		}

		// Severity↔confidence consistency: LOW confidence caps severity at MEDIUM.
		if conf == "LOW" {
			rank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
			if rank[sev] > rank["MEDIUM"] {
				t.Errorf("%s violates severity↔confidence consistency: severity=%s with confidence=LOW", path, sev)
			}
		}
	}
}

// --- assertion helpers -------------------------------------------------------

func requireKeys(t *testing.T, path string, m map[string]any, keys []string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("%s missing required field %q", path, k)
		}
	}
}

func requireObject(t *testing.T, path string, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s expected object, got %T", path, v)
	}
	return m
}

func requireArray(t *testing.T, path string, v any) []any {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("%s expected array, got %T", path, v)
	}
	return a
}

func requireString(t *testing.T, path string, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Errorf("%s expected string, got %T (%v)", path, v, v)
	}
	return s
}

func requireBool(t *testing.T, path string, v any) {
	t.Helper()
	if _, ok := v.(bool); !ok {
		t.Errorf("%s expected bool, got %T", path, v)
	}
}

func requireInt(t *testing.T, path string, v any) {
	t.Helper()
	// JSON numbers decode to float64 unless json.Number is requested.
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			t.Errorf("%s expected integer, got fractional %v", path, n)
		}
	case json.Number:
		if _, err := n.Int64(); err != nil {
			t.Errorf("%s expected integer, got %v", path, n)
		}
	default:
		t.Errorf("%s expected number, got %T", path, v)
	}
}

func requireEnum(t *testing.T, path string, v any, allowed []string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Errorf("%s expected string enum, got %T", path, v)
		return ""
	}
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	t.Errorf("%s = %q, must be one of %v", path, s, allowed)
	return s
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// --- tests -------------------------------------------------------------------

// schemaSampleFindings exercises every enum value at least once.
func schemaSampleFindings() []models.Finding {
	line1 := "src/config.py:14"
	line6 := "app/views.py:15"
	return []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS header", Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /api/users", Evidence: "HSTS missing", Fix: "Add Strict-Transport-Security", References: []string{"CWE-319"}, Confidence: models.ConfidenceHigh},
		{ID: "SEC-002", Title: "Hardcoded secret", Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets", Endpoint: "src/config.py:14", Evidence: "API_KEY = '...'", Fix: "Use env var", References: []string{"CWE-798"}, Confidence: models.ConfidenceHigh, Line: &line1},
		{ID: "SEC-003", Title: "Auth bypass", Severity: models.SeverityCritical, Source: models.SourceCorrelated, Category: "auth_bypass", Endpoint: "GET /api/admin", AffectedEndpoints: []string{"GET /api/admin", "GET /api/admin/users"}, Evidence: "200 without auth | Code: no @login_required", Fix: "Add auth", References: []string{"CWE-306"}, Confidence: models.ConfidenceHigh},
		{ID: "SEC-004", Title: "Server fingerprint", Severity: models.SeverityInfo, Source: models.SourceBlackbox, Category: "info_disclosure", Endpoint: "GET /api/health", Evidence: "Server: nginx/1.18.0", Fix: "Strip Server header", References: []string{"CWE-200"}, Confidence: models.ConfidenceLow},
		{ID: "SEC-005", Title: "Boolean SQLi candidate", Severity: models.SeverityLow, Source: models.SourceBlackbox, Category: "injection", Endpoint: "GET /api/items", Evidence: "Length-delta on payload", Fix: "Parameterize", References: []string{"CWE-89"}, Confidence: models.ConfidenceMedium},
		{
			ID: "SEC-006", Title: "Reachable SQLi", Severity: models.SeverityCritical, Source: models.SourceCorrelated, Category: "injection",
			Endpoint: "app/views.py:15", Evidence: "user input flows into cursor.execute", Fix: "Use parameterized queries",
			References: []string{"CWE-89"}, Confidence: models.ConfidenceHigh, Line: &line6,
			TaintChain: []models.TaintLink{
				{File: "app/views.py", Line: 12, Expr: "q = request.args.get('q')"},
				{File: "app/views.py", Line: 14, Expr: "sql = 'SELECT ...' + q"},
				{File: "app/views.py", Line: 15, Expr: "cursor.execute(sql)"},
			},
			Reachable: true,
		},
	}
}

func TestJSONReport_ValidatesAgainstSchema(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:         "https://api.example.com",
		StartedAt:      time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC),
		Duration:       "12.5s",
		Version:        "0.5.0-dev",
		Mode:           "hybrid",
		EndpointsCount: 21,
		ActiveProbes:   false,
		ChecksRun:      []string{"headers", "cors", "exposure", "ratelimit", "secrets", "semgrep", "deps"},
	}

	if err := RenderJSON(&buf, schemaSampleFindings(), meta); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	validateAgainstSchema(t, report)
}

func TestJSONReport_EmptyFindingsValidatesAgainstSchema(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:         "https://api.example.com",
		StartedAt:      time.Now().UTC(),
		Duration:       "0s",
		Version:        "0.5.0-dev",
		Mode:           "blackbox",
		EndpointsCount: 0,
		ActiveProbes:   false,
	}

	if err := RenderJSON(&buf, nil, meta); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	validateAgainstSchema(t, report)
}

// Severity↔confidence consistency is tested both at render-time (the validator
// catches violations in the JSON output) and as a unit test on the enforcer
// itself — see models.TestEnforceSeverityConsistency.
func TestJSONReport_LowConfidenceWithHighSeverityIsCaughtBySchema(t *testing.T) {
	bad := []models.Finding{{
		ID: "SEC-001", Title: "Bogus", Severity: models.SeverityHigh,
		Source: models.SourceBlackbox, Category: "headers",
		Endpoint: "GET /", Evidence: "x", Fix: "y",
		References: []string{}, Confidence: models.ConfidenceLow,
	}}
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "x", StartedAt: time.Now().UTC(), Duration: "0s", Version: "dev", Mode: "blackbox", EndpointsCount: 1}
	if err := RenderJSON(&buf, bad, meta); err != nil {
		t.Fatal(err)
	}

	var report map[string]any
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}

	// Use a sub-test recorder to verify the rule fires.
	rec := &testing.T{}
	validateAgainstSchema(rec, report)
	if !rec.Failed() {
		t.Fatal("expected schema validator to flag HIGH severity + LOW confidence")
	}
}
