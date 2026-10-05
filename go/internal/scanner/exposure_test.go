package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestCheckExposure_PasswordField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"username": "admin", "password": "supersecret123", "email": "a@b.com"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users/1", FullURL: server.URL + "/api/users/1"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for password exposure")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Password exposed in API response" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("password exposure should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing password exposure finding")
	}
}

func TestCheckExposure_SecretField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"api_key": "sk-live-1234567890abcdef", "name": "test"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/config", FullURL: server.URL + "/api/config"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Secret or API key exposed in API response" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("secret exposure should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing secret exposure finding")
	}
}

func TestCheckExposure_TokenField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmnop"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "POST", Path: "/api/login", FullURL: server.URL + "/api/login"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Token exposed in API response" {
			found = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("token exposure should be HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing token exposure finding")
	}
}

func TestCheckExposure_StackTrace(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Python traceback",
			body: `{"error": "Internal Server Error", "detail": "Traceback (most recent call last):\n  File \"app.py\", line 42"}`,
		},
		{
			name: "Go panic",
			body: `panic: runtime error: index out of range [3] with length 3`,
		},
		{
			name: "Java stack trace",
			body: `Exception in thread "main" java.lang.NullPointerException`,
		},
		{
			name: "Node.js stack trace",
			body: `{"stack": "at Object.<anonymous> (/app/server.js:15:5)"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/api/error", FullURL: server.URL + "/api/error"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

			findings := CheckExposure(context.Background(), cfg, ep)
			found := false
			for _, f := range findings {
				if f.Title == "Stack trace in error response" {
					found = true
					if f.Severity != models.SeverityMedium {
						t.Errorf("stack trace should be MEDIUM, got %s", f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("missing stack trace finding for %s", tt.name)
			}
		})
	}
}

func TestCheckExposure_InternalIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"server": "10.0.1.42", "status": "ok"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/status", FullURL: server.URL + "/api/status"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Internal IP address disclosed in response" {
			found = true
			if f.Severity != models.SeverityLow {
				t.Errorf("internal IP should be LOW, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing internal IP finding")
	}
}

func TestCheckExposure_VersionString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"app": "myapp", "version": "3.14.1"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/info", FullURL: server.URL + "/api/info"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Software version string in response" {
			found = true
			if f.Severity != models.SeverityInfo {
				t.Errorf("version string should be INFO, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing version string finding")
	}
}

// 4.12: masked/placeholder password values must not flag CRITICAL —
// real values still must.
func TestCheckExposure_MaskedPasswordGuard(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool // expect a password finding
	}{
		{name: "all asterisks", body: `{"password":"********"}`, want: false},
		{name: "REDACTED", body: `{"password":"REDACTED"}`, want: false},
		{name: "bullets", body: `{"password":"••••••"}`, want: false},
		{name: "x mask", body: `{"password":"xxxxxxxx"}`, want: false},
		{name: "literal stars", body: `{"password":"***"}`, want: false},
		{name: "real value", body: `{"password":"hunter2realvalue"}`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/api/u", FullURL: server.URL + "/api/u"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckExposure(context.Background(), cfg, ep)

			found := false
			for _, f := range findings {
				if f.Title == "Password exposed in API response" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("password finding=%v, want %v (body=%s)", found, tt.want, tt.body)
			}
		})
	}
}

// 4.15: i18n / UI-label dictionaries surface the word "password" as a
// translation string, not a credential. They must not flag CRITICAL,
// while genuine single-record password leaks still must.
func TestCheckExposure_I18nLabelTable(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool // expect a password finding
	}{
		{
			// mirrors the real /api/support/translations/flat/ FP: a big
			// en/ar string table whose "password" value is the label itself.
			name: "full translations table (en+ar)",
			body: `{"en":{"password":"Password","passwordHint":"Please enter your password","forgotPassword":"Forgot password?","newPassword":"New password","confirmPassword":"Confirm password","changePassword":"Change password","currentPassword":"Current Password"},"ar":{"password":"كلمة المرور","forgotPassword":"نسيت كلمة المرور؟","newPassword":"كلمة المرور الجديدة"}}`,
			want: false,
		},
		{
			// small label table: a couple of password-family keys plus a
			// label-shaped value → still i18n, not a leak.
			name: "small label table, english label value",
			body: `{"password":"Password","forgotPassword":"Forgot password?"}`,
			want: false,
		},
		{
			// non-Latin single-word label alongside a sibling key.
			name: "arabic label value with sibling",
			body: `{"password":"كلمة المرور","newPassword":"كلمة المرور الجديدة"}`,
			want: false,
		},
		{
			// genuine leak: a real credential value next to password
			// metadata timestamps must still fire (value isn't label-like).
			name: "real credential with password_changed_at sibling",
			body: `{"username":"admin","password":"supersecret123","password_changed_at":"2024-01-01T00:00:00Z"}`,
			want: true,
		},
		{
			// lone weak-credential leak (the value happens to be the word
			// "password") has no sibling keys → still flagged.
			name: "lone weak password literal",
			body: `{"password":"password"}`,
			want: true,
		},
		{
			// regression: a serialized user row that leaks its plaintext
			// password alongside its own password-metadata columns. The value
			// is plainly a credential, so the many password-named keys must
			// NOT suppress it (the old >=5 key-count rule did).
			name: "verbose user record with plaintext password",
			body: `{"id":1,"username":"admin","password":"S3cr3tP@ss","password_hash":"abc","password_salt":"def","password_changed_at":"2024-01-01","password_expires_at":"2025-01-01","password_reset_token":"tok"}`,
			want: true,
		},
		{
			// regression: a combined SSR/bootstrap payload bundling an i18n
			// label table with a live user object. The real credential lives
			// in user.password, after the label table — the guard must scan
			// every "password" value, not just the first one Find() returns.
			name: "i18n label table plus real user record",
			body: `{"i18n":{"password":"Password","passwordHint":"hint","forgotPassword":"f","newPassword":"n","confirmPassword":"c"},"user":{"username":"admin","password":"RealLeak123"}}`,
			want: true,
		},
		{
			// regression: a single-word non-Latin value is at least as likely
			// to be a real password as a translation, so it must not be
			// auto-classified as a label on script alone.
			name: "non-latin single-word credential with sibling",
			body: `{"password":"пароль123","newPassword":"x"}`,
			want: true,
		},
		{
			// regression: kebab-case i18n label tables (new-password, …) are
			// the same FP class as snake/camel and must also be suppressed —
			// the password-family key regex now matches hyphenated keys.
			name: "kebab-case i18n label table",
			body: `{"password":"Password","new-password":"New password","forgot-password":"Forgot password?","confirm-password":"Confirm password","change-password":"Change password"}`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/api/i18n", FullURL: server.URL + "/api/i18n"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckExposure(context.Background(), cfg, ep)

			found := false
			for _, f := range findings {
				if f.Title == "Password exposed in API response" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("password finding=%v, want %v (body=%s)", found, tt.want, tt.body)
			}
		})
	}
}

// 4.13: value-shape secret patterns independent of key name.
func TestCheckExposure_ValueShapeSecrets(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantTitle string
		wantSev   models.Severity
	}{
		{
			name:      "JWT in body",
			body:      `{"data":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`,
			wantTitle: "JWT exposed in API response",
			wantSev:   models.SeverityHigh,
		},
		{
			name:      "AWS access key",
			body:      `{"key":"AKIAIOSFODNN7EXAMPLE"}`,
			wantTitle: "AWS access key exposed in API response",
			wantSev:   models.SeverityCritical,
		},
		{
			name:      "PEM private key",
			body:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			wantTitle: "Private key exposed in API response",
			wantSev:   models.SeverityCritical,
		},
		{
			name:      "client_secret key",
			body:      `{"client_secret":"abcdef0123456789ZZ"}`,
			wantTitle: "Secret or API key exposed in API response",
			wantSev:   models.SeverityCritical,
		},
		{
			name:      "private_key field",
			body:      `{"private_key":"abcdef0123456789ZZ"}`,
			wantTitle: "Secret or API key exposed in API response",
			wantSev:   models.SeverityCritical,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/api/x", FullURL: server.URL + "/api/x"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckExposure(context.Background(), cfg, ep)

			var got *ev.Evidence
			for i := range findings {
				if findings[i].Title == tt.wantTitle {
					got = &findings[i]
				}
			}
			if got == nil {
				t.Fatalf("missing finding %q for body %s", tt.wantTitle, tt.body)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", got.Severity, tt.wantSev)
			}
		})
	}
}

// 4.14: stack_trace + internal_ip precision. Prose must not FP; real
// stack frames / IPs must still fire.
func TestCheckExposure_StackTracePrecision(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "prose at home", body: `{"msg":"Meet me at home (tomorrow)"}`, want: false},
		{name: "real java frame", body: `at com.foo.Bar.baz(Bar.java:42)`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			ep := Endpoint{Method: "GET", Path: "/e", FullURL: server.URL + "/e"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckExposure(context.Background(), cfg, ep)
			found := false
			for _, f := range findings {
				if f.Title == "Stack trace in error response" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("stack_trace found=%v, want %v (body=%s)", found, tt.want, tt.body)
			}
		})
	}
}

func TestCheckExposure_InternalIPPrecision(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "version string", body: `{"v":"version 10.20.30"}`, want: false},
		{name: "price", body: `{"p":"$192.168"}`, want: false},
		{name: "real ip", body: `{"host":"10.0.0.5"}`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			ep := Endpoint{Method: "GET", Path: "/s", FullURL: server.URL + "/s"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
			findings := CheckExposure(context.Background(), cfg, ep)
			found := false
			for _, f := range findings {
				if f.Title == "Internal IP address disclosed in response" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("internal_ip found=%v, want %v (body=%s)", found, tt.want, tt.body)
			}
		})
	}
}

func TestCheckExposure_CleanResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id": 1, "name": "John", "email": "john@example.com"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users/1", FullURL: server.URL + "/api/users/1"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean response, got %d", len(findings))
	}
}

func TestCheckExposure_MultiplePatterns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"password": "hunter2", "api_key": "sk-live-abcdefghijklmnop", "server": "192.168.1.100"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/dump", FullURL: server.URL + "/api/dump"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings for multiple patterns, got %d", len(findings))
	}
}

func TestCheckExposure_EvidenceTruncation(t *testing.T) {
	longSecret := `"api_key": "` + string(make([]byte, 300)) + `"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{%s}`, longSecret)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: server.URL + "/api/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	for _, f := range findings {
		if len(f.Evidence) > maxEvidenceLen+10 {
			t.Errorf("evidence not truncated: length %d", len(f.Evidence))
		}
	}
}
