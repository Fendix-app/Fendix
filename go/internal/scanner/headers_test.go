package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestCheckHeaders_AllMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)

	// Missing: HSTS, X-Content-Type-Options, X-Frame-Options, CSP = 4 findings
	// Server and X-Powered-By are absent → no info findings (correct behavior)
	if len(findings) < 4 {
		t.Fatalf("expected at least 4 findings for no security headers, got %d", len(findings))
	}

	titles := make(map[string]bool)
	for _, f := range findings {
		titles[f.Title] = true
		if f.Source != models.SourceBlackbox {
			t.Errorf("expected source blackbox, got %s for %s", f.Source, f.Title)
		}
		if f.Category != "headers" {
			t.Errorf("expected category headers, got %s for %s", f.Category, f.Title)
		}
	}

	expected := []string{
		"Missing Strict-Transport-Security header",
		"Missing or incorrect X-Content-Type-Options header",
		"Missing or incorrect X-Frame-Options header",
		"Missing Content-Security-Policy header",
	}
	for _, title := range expected {
		if !titles[title] {
			t.Errorf("missing expected finding: %s", title)
		}
	}
}

// TASK-123 / FP corpus pattern P2: missing-header findings on a 404 page
// aren't actionable. The scanner should skip the check entirely.
func TestCheckHeaders_SkipsOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/missing", FullURL: server.URL + "/missing"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404 (header check should skip), got %d: %v", len(findings), findings)
	}
}

func TestCheckHeaders_SkipsOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/broken", FullURL: server.URL + "/broken"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 500, got %d", len(findings))
	}
}

func TestCheckHeaders_RunsOn3xxRedirect(t *testing.T) {
	// 3xx responses are real responses (real headers gate cross-origin
	// requests during redirect chains). The gate is "skip 4xx+ only."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(301)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/redirect", FullURL: server.URL + "/redirect"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("expected findings on 3xx (still a real response), got 0")
	}
}

func TestCheckHeaders_AllPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// 4.10: modern headers must be present too, or they'd flag.
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all headers present, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s", f.Title)
		}
	}
}

func TestCheckHeaders_SeverityMapping(t *testing.T) {
	tests := []struct {
		name             string
		setHeaders       func(w http.ResponseWriter)
		expectedSeverity models.Severity
		expectedTitle    string
	}{
		{
			name:             "HSTS missing is MEDIUM",
			setHeaders:       func(w http.ResponseWriter) {},
			expectedSeverity: models.SeverityMedium,
			expectedTitle:    "Missing Strict-Transport-Security header",
		},
		{
			name: "X-Content-Type-Options wrong value is LOW",
			setHeaders: func(w http.ResponseWriter) {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
				w.Header().Set("X-Content-Type-Options", "wrong")
			},
			expectedSeverity: models.SeverityLow,
			expectedTitle:    "Missing or incorrect X-Content-Type-Options header",
		},
		{
			name: "X-Frame-Options SAMEORIGIN is OK",
			setHeaders: func(w http.ResponseWriter) {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
				// 4.10: modern headers present so only X-Frame-Options is under test.
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.Header().Set("Permissions-Policy", "geolocation=()")
				w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
				w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
				w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			},
			expectedSeverity: "",
			expectedTitle:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.setHeaders(w)
				w.WriteHeader(200)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckHeaders(context.Background(), cfg, ep)

			if tt.expectedTitle == "" {
				if len(findings) != 0 {
					t.Fatalf("expected 0 findings, got %d", len(findings))
				}
				return
			}

			found := false
			for _, f := range findings {
				if f.Title == tt.expectedTitle {
					found = true
					if f.Severity != tt.expectedSeverity {
						t.Errorf("severity for %q: got %s, want %s", f.Title, f.Severity, tt.expectedSeverity)
					}
				}
			}
			if !found {
				t.Errorf("expected finding %q not found", tt.expectedTitle)
			}
		})
	}
}

func TestCheckHeaders_ServerVersionDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// 4.10: modern headers present so only the Server-version finding fires.
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Server", "nginx/1.21.3")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for server version, got %d", len(findings))
	}
	if findings[0].Title != "Server version disclosed in header" {
		t.Fatalf("expected server-version finding, got %q", findings[0].Title)
	}
	if findings[0].Severity != models.SeverityInfo {
		t.Errorf("server version disclosure should be INFO, got %s", findings[0].Severity)
	}
}

func TestCheckHeaders_XPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// 4.10: modern headers present so only the X-Powered-By finding fires.
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for X-Powered-By, got %d", len(findings))
	}
	if findings[0].Title != "X-Powered-By header discloses technology" {
		t.Errorf("unexpected finding title: %s", findings[0].Title)
	}
}

// 4.8: CSP directive depth. A PRESENT-but-weak CSP now emits a distinct
// "Weak Content-Security-Policy" finding; a strong CSP emits nothing; an
// absent header keeps the existing "Missing Content-Security-Policy"
// finding (covered by TestCheckHeaders_AllMissing).
func TestCheckHeaders_WeakCSP(t *testing.T) {
	// Helper: build a fully-headered response so only the CSP under test varies.
	strong := func(w http.ResponseWriter, csp string) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", csp)
	}

	tests := []struct {
		name          string
		csp           string
		wantWeak      bool
		wantSeverity  models.Severity
		wantNoFinding bool
	}{
		{name: "unsafe-inline in script-src", csp: "script-src 'unsafe-inline'", wantWeak: true, wantSeverity: models.SeverityMedium},
		{name: "wildcard default-src", csp: "default-src *", wantWeak: true, wantSeverity: models.SeverityMedium},
		{name: "strong policy", csp: "default-src 'self'", wantNoFinding: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				strong(w, tt.csp)
				w.WriteHeader(200)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckHeaders(context.Background(), cfg, ep)

			var weak *ev.Evidence
			for i := range findings {
				if findings[i].Title == "Weak Content-Security-Policy" {
					weak = &findings[i]
				}
				if findings[i].Title == "Missing Content-Security-Policy header" {
					t.Errorf("CSP present but emitted missing-CSP finding")
				}
			}
			if tt.wantNoFinding {
				if weak != nil {
					t.Errorf("expected no weak-CSP finding for %q, got %q", tt.csp, weak.Evidence)
				}
				return
			}
			if weak == nil {
				t.Fatalf("expected Weak-CSP finding for %q", tt.csp)
			}
			if weak.Severity != tt.wantSeverity {
				t.Errorf("weak CSP severity = %s, want %s", weak.Severity, tt.wantSeverity)
			}
		})
	}
}

// 4.9: HSTS depth. Absent → existing missing finding; max-age=0 or no
// max-age directive → "HSTS disabled" MEDIUM; max-age < 180d →
// "HSTS max-age too short" LOW; max-age >= 180d → no finding.
func TestCheckHeaders_HSTSDepth(t *testing.T) {
	other := func(w http.ResponseWriter) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	}

	tests := []struct {
		name      string
		hsts      string // "" means do not set
		setHSTS   bool
		wantTitle string // "" means expect no HSTS finding
		wantSev   models.Severity
	}{
		{name: "absent", setHSTS: false, wantTitle: "Missing Strict-Transport-Security header", wantSev: models.SeverityMedium},
		{name: "max-age=0", setHSTS: true, hsts: "max-age=0", wantTitle: "HSTS disabled", wantSev: models.SeverityMedium},
		{name: "too short", setHSTS: true, hsts: "max-age=100", wantTitle: "HSTS max-age too short", wantSev: models.SeverityLow},
		{name: "strong", setHSTS: true, hsts: "max-age=31536000", wantTitle: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other(w)
				if tt.setHSTS {
					w.Header().Set("Strict-Transport-Security", tt.hsts)
				}
				w.WriteHeader(200)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckHeaders(context.Background(), cfg, ep)

			var hstsFinding *ev.Evidence
			for i := range findings {
				switch findings[i].Title {
				case "Missing Strict-Transport-Security header", "HSTS disabled", "HSTS max-age too short":
					hstsFinding = &findings[i]
				}
			}
			if tt.wantTitle == "" {
				if hstsFinding != nil {
					t.Errorf("expected no HSTS finding for %q, got %q", tt.hsts, hstsFinding.Title)
				}
				return
			}
			if hstsFinding == nil {
				t.Fatalf("expected HSTS finding %q for %q", tt.wantTitle, tt.hsts)
			}
			if hstsFinding.Title != tt.wantTitle {
				t.Errorf("HSTS title = %q, want %q", hstsFinding.Title, tt.wantTitle)
			}
			if hstsFinding.Severity != tt.wantSev {
				t.Errorf("HSTS severity = %s, want %s", hstsFinding.Severity, tt.wantSev)
			}
		})
	}
}

// 4.10: modern security headers. A response missing Referrer-Policy
// produces a Referrer-Policy finding; present-good values produce none.
func TestCheckHeaders_ModernHeaders(t *testing.T) {
	// Missing Referrer-Policy (everything else present).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		// Referrer-Policy intentionally omitted.
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	findings := CheckHeaders(context.Background(), cfg, ep)

	found := false
	for _, f := range findings {
		if f.Title == "Missing Referrer-Policy header" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Referrer-Policy finding when header absent")
	}

	// All modern headers present → none of the modern-header findings.
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.WriteHeader(200)
	}))
	defer server2.Close()
	ep2 := Endpoint{Method: "GET", Path: "/test", FullURL: server2.URL + "/test"}
	findings2 := CheckHeaders(context.Background(), cfg, ep2)
	if len(findings2) != 0 {
		t.Errorf("expected 0 findings when all headers present, got %d: %+v", len(findings2), findings2)
	}
}

// 4.11: HSTS/CSP are app-wide regardless of auth, so a 401 response
// missing HSTS must still produce the HSTS finding (previously the
// >=400 gate suppressed it). 404 stays skipped (TASK-123).
func TestCheckHeaders_RunsOn401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/secure", FullURL: server.URL + "/secure"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Missing Strict-Transport-Security header" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HSTS finding on 401 (transport headers are app-wide), got %d findings", len(findings))
	}
}

func TestCheckHeaders_WithAuth(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{
		Timeout:      10,
		AllowPrivate: true,
		Auth: &models.AuthContext{
			Type:   "bearer",
			Value:  "Bearer testtoken",
			Header: "Authorization",
		},
	}

	CheckHeaders(context.Background(), cfg, ep)
	if receivedAuth != "Bearer testtoken" {
		t.Errorf("expected auth header to be sent, got %q", receivedAuth)
	}
}

func TestContainsVersion(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"nginx/1.21.3", true},
		{"Apache/2.4.52", true},
		{"nginx", false},
		{"cloudflare", false},
		{"gunicorn/20.1.0", true},
		{"", false},
		{"1.0", true},
		// 4.7: real version tokens only, full-string scan (final byte reachable).
		{"nginx/1.21.0", true},
		{"Apache/2.4", true},
		{"MyServer 2.0", true}, // version is the final token — must be reachable
		// 4.7: benign Server values that previously false-positived on the
		// old byte-scan ("N." or "/N" substrings) must NOT flag.
		{"Microsoft-IIS", false}, // contains no version token
		{"Caddy", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			result := containsVersion(tt.value)
			if result != tt.expected {
				t.Errorf("containsVersion(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

// TestCheckHeaders_LogaggCapsTransientErrors is the regression test for
// TASK-094 logging hygiene. Real-world scans against partially-unreachable
// targets used to flood logs with one slog.Warn per failed request. Now
// CheckHeaders routes its transient-error WARN through logagg, which caps
// per-key emission at DefaultCap and downgrades the rest to slog.Debug.
//
// The fixture is a server that immediately closes every connection so the
// request fails consistently. Calling CheckHeaders 10 times should produce
// at most DefaultCap WARN-level emissions tracked under key="headers".
func TestCheckHeaders_LogaggCapsTransientErrors(t *testing.T) {
	logagg.Reset()
	defer logagg.Reset()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Start()
	server.Close() // close immediately so subsequent dials fail

	cfg := &models.ScanConfig{Timeout: 1, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: server.URL + "/"}

	const calls = 10
	for i := 0; i < calls; i++ {
		_ = CheckHeaders(context.Background(), cfg, ep)
	}

	warned, suppressed := logagg.Stats("headers")
	if warned != logagg.DefaultCap {
		t.Errorf("warned: got %d, want %d", warned, logagg.DefaultCap)
	}
	if warned+suppressed != calls {
		t.Errorf("total events: warned=%d suppressed=%d sum=%d, want %d", warned, suppressed, warned+suppressed, calls)
	}
}

// TestHeaders_DirectObservationOnPresenceChecksOnly locks the predicate this
// file commits to: DirectObservation is set exactly when the check asserts
// ConfidenceHigh from a literal read of the header. It is what makes the
// confidence scorer's +30 auditable — a reader can decide, per finding, whether
// the claim really is "what the wire said".
func TestHeaders_DirectObservationOnPresenceChecksOnly(t *testing.T) {
	t.Run("presence and literal-value checks are direct observations", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		defer server.Close()

		ep := Endpoint{Method: "GET", Path: "/api/v1/users", FullURL: server.URL + "/api/v1/users"}
		findings := CheckHeaders(context.Background(), &models.ScanConfig{Timeout: 10, AllowPrivate: true}, ep)
		if len(findings) == 0 {
			t.Fatal("no findings for a response with no security headers — test premise broken")
		}
		for _, f := range findings {
			if !f.DirectObservation {
				t.Errorf("%q is not marked DirectObservation; a missing header is a deterministic\n"+
					"read of the response", f.Title)
			}
			if f.Confidence != models.ConfidenceHigh {
				t.Errorf("%q carries DirectObservation but not ConfidenceHigh — the two must agree\n"+
					"in this file", f.Title)
			}
		}
	})

	t.Run("weak-CSP is an inference, not a read", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'")
			w.WriteHeader(200)
		}))
		defer server.Close()

		ep := Endpoint{Method: "GET", Path: "/api/v1/users", FullURL: server.URL + "/api/v1/users"}
		findings := CheckHeaders(context.Background(), &models.ScanConfig{Timeout: 10, AllowPrivate: true}, ep)

		var weak *ev.Evidence
		for i := range findings {
			if findings[i].Title == "Weak Content-Security-Policy" {
				weak = &findings[i]
			}
		}
		if weak == nil {
			t.Fatalf("no Weak-CSP finding for an unsafe-inline policy: %v", findings)
		}
		if weak.DirectObservation {
			t.Error("Weak Content-Security-Policy claimed the direct-observation bonus — analyzeCSP\n" +
				"GRADES a policy (a nonce/'strict-dynamic' policy listing 'unsafe-inline' as a\n" +
				"legacy fallback is not actually weak), so the claim is an inference")
		}
	})
}
