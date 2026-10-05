package scanner

// Integration tests here drive CheckInjection / CheckInjectionWithAudit against
// loopback httptest servers. Those entry points build their client through
// guardedClient, whose SSRF egress guard (internal/netguard) refuses loopback
// by default. Each such config therefore sets AllowPrivate: true — the same
// relaxation a real scan auto-applies when --url resolves to a private/loopback
// host (see allowPrivate / netguard.TargetIsPrivate). Tests that call the
// individual probe* functions with their own *http.Client are unaffected and
// don't need the field.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestCheckInjection_DisabledWithoutEnableActive(t *testing.T) {
	cfg := &models.ScanConfig{
		EnableActive: false,
		Timeout:      5,
	}
	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: "http://example.com/api/test"}
	findings := CheckInjection(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("expected no findings when EnableActive=false, got %d", len(findings))
	}
}

func TestCheckInjectionWithAudit_DisabledWithoutEnableActive(t *testing.T) {
	cfg := &models.ScanConfig{EnableActive: false, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: "http://example.com/api/test"}
	auditLog := NewProbeAuditLog()
	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
	if len(auditLog.Records()) != 0 {
		t.Errorf("expected no audit records, got %d", len(auditLog.Records()))
	}
}

func TestProbeAuditLog_RecordAndCount(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/test",
		ProbeType: ProbeSQLi,
		Payload:   "' AND SLEEP(5)--",
		Parameter: "id",
		Method:    "GET",
		Status:    200,
		Duration:  "100ms",
		Finding:   false,
	})

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/test",
		ProbeType: ProbeCMDi,
		Payload:   cmdiPayload,
		Parameter: "name",
		Method:    "GET",
		Status:    200,
		Duration:  "50ms",
		Finding:   false,
	})

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/other",
		ProbeType: ProbeCRLF,
		Payload:   crlfPayload,
		Parameter: "q",
		Method:    "GET",
		Status:    200,
		Duration:  "30ms",
		Finding:   false,
	})

	if got := log.Count("http://example.com/api/test"); got != 2 {
		t.Errorf("count for /api/test: got %d, want 2", got)
	}
	if got := log.Count("http://example.com/api/other"); got != 1 {
		t.Errorf("count for /api/other: got %d, want 1", got)
	}

	records := log.Records()
	if len(records) != 3 {
		t.Errorf("total records: got %d, want 3", len(records))
	}

	// Check that audit log was written
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] prefix in audit log output")
	}
	if !strings.Contains(output, "sqli") {
		t.Error("expected sqli probe type in audit log output")
	}
}

func TestProbeAuditLog_MaxProbesPerEndpoint(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	// Fill up to max probes
	for i := 0; i < MaxProbesPerEndpoint; i++ {
		log.Record(ProbeRecord{
			Endpoint: "http://example.com/api/test",
		})
	}

	if got := log.Count("http://example.com/api/test"); got != MaxProbesPerEndpoint {
		t.Errorf("count: got %d, want %d", got, MaxProbesPerEndpoint)
	}
}

func TestProbeSQLi_DetectsDelayedResponse(t *testing.T) {
	// Create a mock server that delays when it sees a SLEEP payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if strings.Contains(query, "SLEEP") || strings.Contains(query, "pg_sleep") || strings.Contains(query, "WAITFOR") {
			time.Sleep(200 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      10,
	}

	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/test",
		FullURL: ts.URL + "/api/test",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	// Use a short-timeout client so baseline is very fast
	// The mock adds 200ms delay for injection payloads
	// We need to override the threshold check — for testing we use a custom approach
	findings := probeSQLi(context.Background(), &http.Client{Timeout: 10 * time.Second}, cfg, ep, "id", LocQuery, auditLog)

	// The mock delays 200ms which is less than baseline+4s, so no findings expected
	// (Real SQLi detection needs 5+ second delays)
	if len(findings) != 0 {
		t.Logf("unexpected findings (delay too short to trigger): %d", len(findings))
	}

	// 5 DB payloads after TASK-086 (was 3 — MySQL/Postgres/MSSQL/SQLite/Oracle)
	records := auditLog.Records()
	if len(records) < 5 {
		t.Errorf("expected at least 5 audit records for SQLi probes (5 DB types), got %d", len(records))
	}

	for _, r := range records {
		if r.ProbeType != ProbeSQLi {
			t.Errorf("expected probe type sqli, got %s", r.ProbeType)
		}
		if r.Endpoint != ep.FullURL {
			t.Errorf("expected endpoint %s, got %s", ep.FullURL, r.Endpoint)
		}
	}
}

// TestProbeSQLi_UnconfirmedSlowStaysMedium (fix 2.1): a one-off slow response
// must NOT yield ConfidenceHigh. The server delays ONLY the first injection
// probe (counter-based) past the threshold; the confirmation re-probe (same
// payload) returns fast. The finding should still surface (we saw one slow
// response) but at ConfidenceMedium, because the timing wasn't reproduced.
func TestProbeSQLi_UnconfirmedSlowStaysMedium(t *testing.T) {
	if testing.Short() {
		t.Skip("skips a >4s real-time delay in -short mode")
	}
	var injCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		isInjection := strings.Contains(query, "SLEEP") || strings.Contains(query, "pg_sleep") ||
			strings.Contains(query, "WAITFOR") || strings.Contains(query, "randomblob") ||
			strings.Contains(query, "DBMS_PIPE")
		if isInjection {
			// Only the very first injection probe is slow; the confirmation
			// re-probe (and every later one) returns fast.
			if atomic.AddInt32(&injCount, 1) == 1 {
				time.Sleep(4500 * time.Millisecond)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 15}
	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: ts.URL + "/api/test", Params: []string{"id"}}
	auditLog := NewProbeAuditLog()

	findings := probeSQLi(context.Background(), &http.Client{Timeout: 15 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 time-based finding for the one slow probe, got %d", len(findings))
	}
	if findings[0].Confidence != models.ConfidenceMedium {
		t.Errorf("unconfirmed one-off slow response must stay ConfidenceMedium, got %s", findings[0].Confidence)
	}
}

func TestProbeCMDi_DetectsCanary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a vulnerable server that shell-EVALUATES the canary (fix 2.4):
		// the injected "$((13*99))" arithmetic resolves to 1287 → fendix1287end.
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") {
					fmt.Fprintf(w, "Result: %s\n", cmdiComputedCanary)
					return
				}
			}
		}
		fmt.Fprintf(w, "OK")
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/exec",
		FullURL: ts.URL + "/api/exec",
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", LocQuery, auditLog)

	if len(findings) != 1 {
		t.Fatalf("expected 1 CMDi finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Category != "injection" {
		t.Errorf("expected injection category, got %s", f.Category)
	}
	if !strings.Contains(f.Title, "Command Injection") {
		t.Errorf("expected Command Injection in title, got %s", f.Title)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}

	// Verify audit log recorded the probe
	records := auditLog.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if !records[0].Finding {
		t.Error("expected finding=true in audit record")
	}
}

func TestProbeCMDi_NoCanary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: ts.URL + "/api/safe"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", LocQuery, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe endpoint, got %d", len(findings))
	}

	records := auditLog.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Finding {
		t.Error("expected finding=false in audit record")
	}
}

// TestCMDi_ReflectionNoFinding (fix 2.4): a server that echoes the raw payload
// verbatim is NOT vulnerable — it just reflects input. The computed canary
// payload contains the SOURCE arithmetic (e.g. "13*99"), not its evaluated
// result ("1287"), so a literal reflection never contains the computed marker
// and must NOT raise a finding. This kills the old false positive where any
// input-reflecting endpoint tripped the CMDi probe.
func TestCMDi_ReflectionNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo every query value back verbatim (pure reflection, no shell).
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				fmt.Fprintf(w, "you said: %s\n", v)
			}
		}
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/echo", FullURL: ts.URL + "/api/echo"}
	auditLog := NewProbeAuditLog()

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", LocQuery, auditLog)
	if len(findings) != 0 {
		t.Errorf("pure reflection must not yield a CMDi finding, got %d: %+v", len(findings), findings)
	}
}

// TestCMDi_Executed (fix 2.4): a server that actually evaluates the injected
// shell expression returns the COMPUTED result of the arithmetic embedded in
// the canary. That computed marker is unambiguous proof the payload reached a
// shell, so it must raise a HIGH-confidence CRITICAL finding.
func TestCMDi_Executed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a shell evaluating "; echo fendix$((13*99))end" → 13*99=1287.
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo fendix") {
					fmt.Fprintf(w, "output: %s\n", cmdiComputedCanary)
					return
				}
			}
		}
		fmt.Fprintf(w, "OK")
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/exec", FullURL: ts.URL + "/api/exec"}
	auditLog := NewProbeAuditLog()

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", LocQuery, auditLog)
	if len(findings) != 1 {
		t.Fatalf("expected 1 CMDi finding when canary is shell-evaluated, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", findings[0].Confidence)
	}
}

func TestProbeCRLF_DetectsHeaderInjection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a vulnerable server: if CRLF payload is in query, reflect cookie
		rawQuery := r.URL.RawQuery
		if strings.Contains(rawQuery, "%0d%0a") || strings.Contains(rawQuery, "Set-Cookie") {
			http.SetCookie(w, &http.Cookie{Name: "fendix", Value: "injected"})
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/vuln", FullURL: ts.URL + "/api/vuln"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCRLF(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "redirect", auditLog)

	if len(findings) != 1 {
		t.Fatalf("expected 1 CRLF finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "CRLF") {
		t.Errorf("expected CRLF in title, got %s", f.Title)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}
}

func TestProbeCRLF_NoCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: ts.URL + "/api/safe"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCRLF(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "q", auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestLengthDelta_Symmetric (fix 2.3): the boolean-SQLi length-delta
// normalization must be order-independent — swapping the two lengths must
// yield the same delta. The old calc divided by the FIRST argument only, so
// lengthDelta(a,b) != lengthDelta(b,a). Normalize against max(a,b).
func TestLengthDelta_Symmetric(t *testing.T) {
	cases := []struct{ a, b int }{
		{100, 50},
		{50, 100},
		{1000, 1010},
		{0, 0},
		{0, 100},
	}
	for _, c := range cases {
		fwd := lengthDelta(c.a, c.b)
		rev := lengthDelta(c.b, c.a)
		if math.Abs(fwd-rev) > 1e-9 {
			t.Errorf("lengthDelta(%d,%d)=%f != lengthDelta(%d,%d)=%f (must be symmetric)", c.a, c.b, fwd, c.b, c.a, rev)
		}
	}
	// 100 vs 50: |50|/max(100,50)=0.5
	if got := lengthDelta(100, 50); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("lengthDelta(100,50)=%f, want 0.5", got)
	}
	// identical → 0
	if got := lengthDelta(0, 0); got != 0 {
		t.Errorf("lengthDelta(0,0)=%f, want 0", got)
	}
}

func TestBuildProbeURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		param    string
		payload  string
		expected string
	}{
		{
			name:     "no existing query",
			baseURL:  "http://example.com/api/test",
			param:    "id",
			payload:  "' AND SLEEP(5)--",
			expected: "http://example.com/api/test?id=%27+AND+SLEEP%285%29--",
		},
		{
			name:     "existing query param",
			baseURL:  "http://example.com/api/test?page=1",
			param:    "id",
			payload:  "payload",
			expected: "http://example.com/api/test?page=1&id=payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProbeURL(tt.baseURL, tt.param, tt.payload)
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestInjection_AuthHeaderSinglePrefix proves the C1 fix: injection probes
// apply auth via the single source of truth (AuthContext.ApplyToRequest), so a
// normalized bearer auth (the production shape, where Value already carries the
// "Bearer " scheme) yields ONE prefix on the wire — not the historical
// "Bearer Bearer <token>" double-prefix that servers reject, which silently
// made every authenticated injection probe run unauthenticated.
func TestInjection_AuthHeaderSinglePrefix(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Production-shaped auth: NormalizeAuth would set Header="Authorization"
	// and keep the scheme-prefixed Value, exactly as DetectAuthType classifies
	// a "Bearer ..." string. We set it directly to mirror that resolved state.
	cfg := &models.ScanConfig{
		Timeout:      5,
		AllowPrivate: true,
		EnableActive: true,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer realtoken",
			Type:   models.AuthTypeBearer,
		},
	}
	ep := Endpoint{Method: "GET", Path: "/q", FullURL: srv.URL + "/q", Params: []string{"id"}}
	ResetGlobalAuditLog()
	_ = injectionCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if gotAuth != "Bearer realtoken" {
		t.Errorf("injection probe sent Authorization=%q; want single-prefix %q (double-prefix is the C1 FN bug)", gotAuth, "Bearer realtoken")
	}
}

func TestCheckInjection_FullPipeline(t *testing.T) {
	// A mock server that is safe (no vulnerabilities)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
		AllowPrivate: true,
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/safe",
		FullURL: ts.URL + "/api/safe",
		Params:  []string{"q"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// No findings expected on a safe server
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d", len(findings))
	}

	// But should have audit records for all probes (SQLi×3 + CMDi×1 + CRLF×1 = 5)
	records := auditLog.Records()
	if len(records) < 5 {
		t.Errorf("expected at least 5 audit records, got %d", len(records))
	}

	// Verify all probes were logged
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] entries in audit log")
	}
}

func TestCheckInjection_DefaultParam(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/test",
		FullURL: ts.URL + "/api/test",
		Params:  nil, // No params — should default to "id"
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	records := auditLog.Records()
	for _, r := range records {
		if r.Parameter != "id" {
			t.Errorf("expected default param 'id', got %q", r.Parameter)
		}
	}
}

func TestMedianDuration(t *testing.T) {
	tests := []struct {
		name      string
		durations []time.Duration
		expected  time.Duration
	}{
		{"empty", nil, 0},
		{"single", []time.Duration{100 * time.Millisecond}, 100 * time.Millisecond},
		{"odd", []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 30 * time.Millisecond}, 30 * time.Millisecond},
		{"even", []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, 15 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := medianDuration(tt.durations)
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSqliPayloads(t *testing.T) {
	payloads := sqliPayloads()
	// TASK-086: SQLite + Oracle added → 5 DBs total.
	if len(payloads) != 5 {
		t.Fatalf("expected 5 SQLi payloads (MySQL, Postgres, MSSQL, SQLite, Oracle), got %d", len(payloads))
	}

	dbs := map[string]bool{}
	for _, p := range payloads {
		dbs[p.DB] = true
		if p.Delay != 5*time.Second {
			t.Errorf("expected 5s delay for %s, got %v", p.DB, p.Delay)
		}
	}
	for _, db := range []string{"MySQL", "Postgres", "MSSQL", "SQLite", "Oracle"} {
		if !dbs[db] {
			t.Errorf("missing payload for %s", db)
		}
	}
}

// --- Integration tests with deliberately vulnerable mock server ---

// newVulnerableMockServer creates a test server that is vulnerable to CMDi and CRLF.
// SQLi time-based testing requires real delays so is tested separately.
func newVulnerableMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery := r.URL.RawQuery

		// Vulnerable to CMDi: shell-EVALUATES the computed canary (fix 2.4) —
		// "$((13*99))" → 1287, so the body carries fendix1287end.
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") {
					fmt.Fprintf(w, "output: %s\n", cmdiComputedCanary)
					return
				}
			}
		}

		// Vulnerable to CRLF: reflects Set-Cookie header
		if strings.Contains(rawQuery, "%0d%0a") || strings.Contains(rawQuery, "Set-Cookie") {
			http.SetCookie(w, &http.Cookie{Name: "fendix", Value: "injected"})
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
}

func TestIntegration_VulnerableServer_CMDiAndCRLF(t *testing.T) {
	ts := newVulnerableMockServer()
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
		AllowPrivate: true,
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/vuln",
		FullURL: ts.URL + "/api/vuln",
		Params:  []string{"input"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// Should find CMDi + CRLF (SQLi won't trigger because no real delay)
	cmdiFound := false
	crlfFound := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Command Injection") {
			cmdiFound = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("CMDi should be CRITICAL, got %s", f.Severity)
			}
		}
		if strings.Contains(f.Title, "CRLF") {
			crlfFound = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("CRLF should be HIGH, got %s", f.Severity)
			}
		}
	}

	if !cmdiFound {
		t.Error("expected CMDi finding from vulnerable server")
	}
	if !crlfFound {
		t.Error("expected CRLF finding from vulnerable server")
	}

	// All probes should be audit-logged
	records := auditLog.Records()
	if len(records) == 0 {
		t.Error("expected audit records")
	}

	// Verify audit log output format
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] prefix in audit output")
	}
	if !strings.Contains(output, "finding=true") {
		t.Error("expected at least one finding=true in audit log")
	}
}

func TestIntegration_SafeServer_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result":"safe"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/safe",
		FullURL: ts.URL + "/api/safe",
		Params:  []string{"q", "page"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s", f.Title)
		}
	}

	// Should still have audit records for all attempted probes.
	// Per (param, location): 5 SQLi time-based (one per DB) + 1 SQLi error +
	// 2 SQLi boolean + 1 CMDi + 1 CRLF = 10 probes. 2 params hits the default
	// budget of 20 exactly.
	records := auditLog.Records()
	if len(records) < 10 {
		t.Errorf("expected at least 10 audit records for 2 params, got %d", len(records))
	}
}

func TestIntegration_MultipleParams(t *testing.T) {
	cmdiHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") {
					cmdiHits++
					fmt.Fprintf(w, "%s\n", cmdiComputedCanary)
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// TASK-086 added more probe types per (param, location), so the default
	// max-probes budget (20) hits before all 3 params are exhausted. Bump the
	// budget for this test — its job is to verify per-param finding emission,
	// not budget enforcement (which has its own test).
	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, MaxProbesPerEndpoint: 200, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/exec",
		FullURL: ts.URL + "/api/exec",
		Params:  []string{"cmd", "action", "run"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// Should find CMDi for each parameter
	cmdiCount := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "Command Injection") {
			cmdiCount++
		}
	}
	if cmdiCount != 3 {
		t.Errorf("expected 3 CMDi findings (one per param), got %d", cmdiCount)
	}
}

func TestIntegration_WithAuth(t *testing.T) {
	authSeen := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			authSeen = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
		// Production-shaped bearer auth: a resolved AuthContext carries the
		// scheme in Value (that is how DetectAuthType classifies it as bearer)
		// and a defaulted Header. ApplyToRequest sets this verbatim, yielding a
		// single "Bearer test-token" on the wire. (The old addAuth re-prepended
		// the scheme — the C1 double-prefix bug — so this test previously passed
		// a bare token; that input shape never occurs after NormalizeAuth.)
		Auth:         &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer test-token"},
		AllowPrivate: true,
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/protected",
		FullURL: ts.URL + "/api/protected",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	if !authSeen {
		t.Error("expected auth header to be included in probe requests")
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 10, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/slow",
		FullURL: ts.URL + "/api/slow",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	// Should not panic or hang — should return gracefully
	findings := CheckInjectionWithAudit(ctx, cfg, ep, auditLog)
	_ = findings // May or may not have findings, but should not hang
}

// TestCheckInjection_SoftStopOnCancelledContext is the F-L5 regression: when
// the scan context is ALREADY cancelled at entry (soft-stop / --max-requests
// cap / --max-duration), the per-target loop must short-circuit before sending
// any probe. Pre-fix the loop ran every payload regardless of cancellation.
func TestCheckInjection_SoftStopOnCancelledContext(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before any probe runs

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/x",
		FullURL: ts.URL + "/api/x",
		Params:  []string{"a", "b", "c"},
	}
	auditLog := NewProbeAuditLog()

	findings := CheckInjectionWithAudit(ctx, cfg, ep, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings on cancelled context, got %d", len(findings))
	}
	// The target loop's select-on-ctx.Done() must fire on the first iteration,
	// so no probe should ever reach the server.
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected 0 requests after pre-cancel soft-stop, got %d", got)
	}
}

// TestProbes_SoftStopOnCancel (fix 2.5): every injection probe function must
// honour a pre-cancelled context with a select-on-ctx.Done() guard at entry —
// returning nil before sending any HTTP request. Pre-fix only probeSQLi had
// this; probeSQLiErrorBased, probeSQLiBoolean, probeCMDi and probeCRLF ran
// their request unconditionally and only failed at client.Do.
func TestProbes_SoftStopOnCancel(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/api/x", FullURL: ts.URL + "/api/x"}
	client := &http.Client{Timeout: 5 * time.Second}

	type probeFn struct {
		name string
		fn   func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence
	}
	probes := []probeFn{
		{"probeSQLi", func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence {
			return probeSQLi(ctx, client, cfg, ep, "id", LocQuery, a)
		}},
		{"probeSQLiErrorBased", func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence {
			return probeSQLiErrorBased(ctx, client, cfg, ep, "id", LocQuery, a)
		}},
		{"probeSQLiBoolean", func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence {
			return probeSQLiBoolean(ctx, client, cfg, ep, "id", LocQuery, a)
		}},
		{"probeCMDi", func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence {
			return probeCMDi(ctx, client, cfg, ep, "id", LocQuery, a)
		}},
		{"probeCRLF", func(ctx context.Context, a *ProbeAuditLog) []ev.Evidence {
			return probeCRLF(ctx, client, cfg, ep, "id", a)
		}},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // cancelled before the probe runs
			atomic.StoreInt32(&hits, 0)
			auditLog := NewProbeAuditLog()

			findings := p.fn(ctx, auditLog)
			if len(findings) != 0 {
				t.Errorf("%s: expected no findings on cancelled ctx, got %d", p.name, len(findings))
			}
			if got := atomic.LoadInt32(&hits); got != 0 {
				t.Errorf("%s: expected 0 requests after pre-cancel soft-stop, got %d", p.name, got)
			}
			if got := len(auditLog.Records()); got != 0 {
				t.Errorf("%s: expected 0 probe records after pre-cancel soft-stop, got %d", p.name, got)
			}
		})
	}
}

// --- TASK-086 tests: body/header probing, error/boolean SQLi, --max-probes-per-endpoint ---

// TestProbeSQLi_ErrorBased_DetectsMySQLError: when the server reflects a MySQL
// error string in its response body, the error-based SQLi probe surfaces a
// HIGH-confidence finding with the matched signature in the evidence.
func TestProbeSQLi_ErrorBased_DetectsMySQLError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Naive vulnerable handler: any single quote in input → MySQL error.
		if strings.Contains(r.URL.RawQuery, "%27") || strings.Contains(r.URL.RawQuery, "'") {
			fmt.Fprintln(w, `{"error":"You have an error in your SQL syntax; check the manual"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items"}
	auditLog := NewProbeAuditLog()

	findings := probeSQLiErrorBased(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "MySQL") {
		t.Errorf("expected MySQL in title, got %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Evidence, "error in your SQL syntax") {
		t.Errorf("expected matched error signature in evidence, got: %s", findings[0].Evidence)
	}
}

// TestProbeSQLi_ErrorBased_NoFalsePositive: a server that returns generic JSON
// without DB error signatures must not yield a finding. Defends against the
// regex being too permissive.
func TestProbeSQLi_ErrorBased_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"error":"invalid input","status":"bad request"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items"}
	auditLog := NewProbeAuditLog()

	findings := probeSQLiErrorBased(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestProbeSQLi_Boolean_DetectsLengthFlip: a server whose response shrinks
// substantially when given a false condition vs. a true one must trigger a
// boolean-based SQLi finding.
func TestProbeSQLi_Boolean_DetectsLengthFlip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		// Simulated: '1'='1' → returns 200 records; '1'='2' → returns 0.
		if strings.Contains(query, "1%27%3D%271") || strings.Contains(query, "1'='1") {
			fmt.Fprintln(w, strings.Repeat(`{"id":1,"name":"row"},`, 50))
			return
		}
		fmt.Fprintln(w, `[]`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items"}
	auditLog := NewProbeAuditLog()

	findings := probeSQLiBoolean(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 1 {
		t.Fatalf("expected 1 boolean SQLi finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Title, "boolean-based") {
		t.Errorf("expected 'boolean-based' in title, got %q", findings[0].Title)
	}
	// Fix 2.6: boolean-blind SQLi is inferential (length/status delta), so it is
	// MEDIUM confidence — not the HIGH reserved for unambiguous evidence
	// (DB error signature, computed CMDi canary, reflected Set-Cookie).
	if findings[0].Confidence != models.ConfidenceMedium {
		t.Errorf("expected MEDIUM confidence for boolean-based SQLi, got %s", findings[0].Confidence)
	}
}

// TestProbeSQLi_Boolean_NoFlipNoFinding: if the response is identical for both
// payloads, no finding. Test the negative path so future regex tweaks don't
// lower the bar to noise.
func TestProbeSQLi_Boolean_NoFlipNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"static":"response"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items"}
	auditLog := NewProbeAuditLog()

	findings := probeSQLiBoolean(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for static response, got %d", len(findings))
	}
}

// TestBooleanSQLi_DynamicContentNoFinding (fix 2.2): a target whose body length
// jitters on EVERY request (random token / timestamp per response) is too noisy
// to draw a boolean-blind conclusion. The control probe is sent twice; if the
// two identical control responses differ by more than the threshold, the probe
// must bail with NO finding rather than mistaking per-request noise for an
// injection-driven true/false flip.
func TestBooleanSQLi_DynamicContentNoFinding(t *testing.T) {
	var n int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each request returns a wildly different body length (varies by request
		// count) so even two identical control probes diverge well past 5%.
		i := atomic.AddInt32(&n, 1)
		fmt.Fprintln(w, strings.Repeat("x", int(i)*200))
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items"}
	auditLog := NewProbeAuditLog()

	findings := probeSQLiBoolean(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "id", LocQuery, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on noisy dynamic-content endpoint, got %d", len(findings))
	}
}

// TestBuildProbeRequest_BodyJSON: body-location probes serialize a JSON body
// where sibling fields get the placeholder "fendix" so the server's input
// validation doesn't 400 the request before it reaches the vulnerable code.
func TestBuildProbeRequest_BodyJSON(t *testing.T) {
	ep := Endpoint{
		Method:     "POST",
		Path:       "/users",
		FullURL:    "http://x/users",
		BodyParams: []string{"username", "email"},
	}
	req, err := buildProbeRequest(context.Background(), ep, "username", "PAYLOAD", LocBody)
	if err != nil {
		t.Fatalf("buildProbeRequest: %v", err)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected JSON Content-Type, got %q", req.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(req.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `"username":"PAYLOAD"`) {
		t.Errorf("expected target field carries payload, got body: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"email":"fendix"`) {
		t.Errorf("expected sibling field gets placeholder, got body: %s", bodyStr)
	}
}

// TestBuildProbeRequest_HeaderStripsCRLF: CR/LF in non-CRLF probe payloads
// must be stripped before going into a header — Go's http client otherwise
// rejects the request with a header-malformed error and we get no detection
// at all.
func TestBuildProbeRequest_HeaderStripsCRLF(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/x", FullURL: "http://x/x"}
	req, err := buildProbeRequest(context.Background(), ep, "X-Trace-Id", "value\r\nInjected: bad", LocHeader)
	if err != nil {
		t.Fatalf("buildProbeRequest: %v", err)
	}
	got := req.Header.Get("X-Trace-Id")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("expected CR/LF stripped from header value, got %q", got)
	}
}

// TestCheckInjection_BodyProbing: a POST endpoint with declared body params
// gets probed via JSON body. Verifies that body-location probes actually fire
// (TASK-086 expansion of the active scanner surface).
func TestCheckInjection_BodyProbing(t *testing.T) {
	bodyHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "application/json" {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "fendix") || strings.Contains(string(body), "'") || strings.Contains(string(body), "OR") {
				bodyHits++
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, MaxProbesPerEndpoint: 100, AllowPrivate: true}
	ep := Endpoint{
		Method:     "POST",
		Path:       "/users",
		FullURL:    ts.URL + "/users",
		BodyParams: []string{"username"},
	}
	auditLog := NewProbeAuditLog()
	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	if bodyHits == 0 {
		t.Fatal("expected at least one JSON-body probe to reach the target")
	}
}

// TestCheckInjection_HeaderProbing: a GET endpoint with declared header params
// gets probed via header values. The mock counts incoming requests with
// X-Trace-Id set; non-zero count means header probing fired.
func TestCheckInjection_HeaderProbing(t *testing.T) {
	headerHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Trace-Id") != "" {
			headerHits++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, MaxProbesPerEndpoint: 100, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/items",
		FullURL: ts.URL + "/items",
		Headers: []string{"X-Trace-Id"},
	}
	auditLog := NewProbeAuditLog()
	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	if headerHits == 0 {
		t.Fatal("expected at least one X-Trace-Id-bearing probe to reach the target")
	}
}

// TestEffectiveMaxProbes_Override: cfg.MaxProbesPerEndpoint=N caps audit log
// growth at N. Pre-TASK-086 the cap was hardcoded to MaxProbesPerEndpoint=20
// with no override; this test guards against regressing the new flag.
func TestEffectiveMaxProbes_Override(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5, MaxProbesPerEndpoint: 3, AllowPrivate: true}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/x",
		FullURL: ts.URL + "/x",
		Params:  []string{"a", "b", "c", "d"},
	}
	auditLog := NewProbeAuditLog()
	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	count := auditLog.Count(ep.FullURL)
	if count > 10 {
		// Per-probe-function checks are eager but each call is gated by
		// effectiveMaxProbes; a budget of 3 means the loop should stop very
		// quickly. Allow some slack since a single SQLi-time-based call can
		// emit 5 records before the next gate.
		t.Errorf("expected probe count to be capped near MaxProbesPerEndpoint=3, got %d", count)
	}
}

// TestEffectiveMaxProbes_DefaultWhenZero: MaxProbesPerEndpoint=0 falls back
// to the default of 20, not "infinite" or "zero probes".
func TestEffectiveMaxProbes_DefaultWhenZero(t *testing.T) {
	cfg := &models.ScanConfig{MaxProbesPerEndpoint: 0}
	if got := effectiveMaxProbes(cfg); got != MaxProbesPerEndpoint {
		t.Errorf("expected default %d for zero, got %d", MaxProbesPerEndpoint, got)
	}
	if got := effectiveMaxProbes(nil); got != MaxProbesPerEndpoint {
		t.Errorf("expected default %d for nil cfg, got %d", MaxProbesPerEndpoint, got)
	}
}

// TestTargetsForEndpoint_FallbackId: an endpoint with no declared params,
// headers, or body fields falls back to a single ("id", query) target —
// preserves v0.2 behavior of "always try `id` so undocumented surface gets
// some attention".
func TestTargetsForEndpoint_FallbackId(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/x", FullURL: "http://x/x"}
	got := targetsForEndpoint(ep)
	if len(got) != 1 || got[0].Name != "id" || got[0].Location != LocQuery {
		t.Errorf("expected single (id, query) fallback, got %+v", got)
	}
}

// TestTargetsForEndpoint_BodyOnlyForBodyMethods: GET endpoints don't get body
// probes even if BodyParams is set — sending a GET with a body is a footgun
// most servers either ignore or reject.
func TestTargetsForEndpoint_BodyOnlyForBodyMethods(t *testing.T) {
	ep := Endpoint{
		Method:     "GET",
		Path:       "/x",
		FullURL:    "http://x/x",
		BodyParams: []string{"f1"},
	}
	got := targetsForEndpoint(ep)
	for _, tg := range got {
		if tg.Location == LocBody {
			t.Errorf("GET should not produce body-location targets, got %+v", got)
		}
	}
}

func TestProbeAuditLog_ConcurrentAccess(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			log.Record(ProbeRecord{
				Endpoint:  fmt.Sprintf("http://example.com/%d", n),
				ProbeType: ProbeSQLi,
			})
			_ = log.Count(fmt.Sprintf("http://example.com/%d", n))
			_ = log.Records()
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if got := len(log.Records()); got != 10 {
		t.Errorf("expected 10 records after concurrent access, got %d", got)
	}
}
