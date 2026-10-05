package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func defaultCfg() *models.ScanConfig {
	return &models.ScanConfig{
		Timeout: 2,
		Workers: 1,
		DelayMs: 0,
	}
}

func makeEndpoint(url string) Endpoint {
	return Endpoint{
		Method:  "GET",
		Path:    "/test",
		FullURL: url + "/test",
	}
}

// ── Malformed Response Tests ────────────────────────────────────────

func TestResilience_GarbageResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		// Write random garbage bytes
		garbage := make([]byte, 4096)
		for i := range garbage {
			garbage[i] = byte(rand.Intn(256))
		}
		w.Write(garbage)
	}))
	defer srv.Close()

	cfg := defaultCfg()
	ep := makeEndpoint(srv.URL)
	checks := []func(ctx context.Context, cfg *models.ScanConfig, ep Endpoint) []ev.Evidence{
		CheckHeaders,
		CheckCORS,
		CheckExposure,
	}

	for _, check := range checks {
		t.Run(fmt.Sprintf("%T", check), func(t *testing.T) {
			// Must not panic
			findings := check(context.Background(), cfg, ep)
			_ = findings
		})
	}
}

func TestResilience_EmptyResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// No body at all
	}))
	defer srv.Close()

	cfg := defaultCfg()
	ep := makeEndpoint(srv.URL)

	findings := CheckExposure(context.Background(), cfg, ep)
	_ = findings // Must not panic

	findings = CheckHeaders(context.Background(), cfg, ep)
	_ = findings
}

func TestResilience_HugeResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Write 5MB of repetitive data
		chunk := strings.Repeat("x", 1024)
		for i := 0; i < 5000; i++ {
			w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	cfg := defaultCfg()
	ep := makeEndpoint(srv.URL)

	// Must complete without hanging or OOM
	findings := CheckExposure(context.Background(), cfg, ep)
	_ = findings
}

func TestResilience_NonUTF8ResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Invalid UTF-8 sequences
		w.Write([]byte{0x80, 0x81, 0xFE, 0xFF, 0xC0, 0xAF})
	}))
	defer srv.Close()

	cfg := defaultCfg()
	ep := makeEndpoint(srv.URL)

	findings := CheckExposure(context.Background(), cfg, ep)
	_ = findings // Must not panic on invalid UTF-8
}

func TestResilience_HTTP500_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal server error","trace":"at com.example.Main.doSomething(Main.java:42)"}`, 500)
	}))
	defer srv.Close()

	cfg := defaultCfg()
	ep := makeEndpoint(srv.URL)

	findings := CheckExposure(context.Background(), cfg, ep)
	_ = findings

	findings = CheckHeaders(context.Background(), cfg, ep)
	_ = findings
}

// ── Timeout Tests ───────────────────────────────────────────────────

func TestResilience_ServerTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server — respond to request context so cleanup is fast
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{
		Timeout: 1, // 1 second timeout
		Workers: 1,
		DelayMs: 0,
	}
	ep := makeEndpoint(srv.URL)

	start := time.Now()
	findings := CheckHeaders(context.Background(), cfg, ep)
	elapsed := time.Since(start)

	// Should return within ~2x timeout, not hang for 5s+
	if elapsed > 3*time.Second {
		t.Errorf("check took %v — should have timed out at %ds", elapsed, cfg.Timeout)
	}
	// Timeout means no findings — not a crash
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on timeout, got %d", len(findings))
	}
}

func TestResilience_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the request context so the handler exits when the client disconnects
		select {
		case <-r.Context().Done():
			return
		case <-time.After(10 * time.Second):
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{
		Timeout: 30,
		Workers: 1,
		DelayMs: 0,
	}
	ep := makeEndpoint(srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	findings := CheckHeaders(ctx, cfg, ep)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("check took %v — context cancellation should have stopped it", elapsed)
	}
	_ = findings
}

// ── Connection Error Tests ──────────────────────────────────────────

func TestResilience_ConnectionRefused(t *testing.T) {
	// Find a port that's not listening
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // Free the port so nothing is listening

	cfg := defaultCfg()
	ep := Endpoint{
		Method:  "GET",
		Path:    "/test",
		FullURL: fmt.Sprintf("http://127.0.0.1:%d/test", port),
	}

	// Must return nil, not panic
	findings := CheckHeaders(context.Background(), cfg, ep)
	if findings != nil {
		t.Errorf("expected nil findings for connection refused, got %d", len(findings))
	}
}

func TestResilience_InvalidURL(t *testing.T) {
	cfg := defaultCfg()
	invalidURLs := []string{
		"not-a-url",
		"://missing-scheme",
		"http://[::1:bad",
		"",
	}

	for _, u := range invalidURLs {
		t.Run(u, func(t *testing.T) {
			ep := Endpoint{Method: "GET", Path: "/", FullURL: u}
			findings := CheckHeaders(context.Background(), cfg, ep)
			_ = findings // Must not panic
		})
	}
}

// ── Slow Drip Response ──────────────────────────────────────────────

func TestResilience_SlowDripResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		w.WriteHeader(200)
		for i := 0; i < 10; i++ {
			w.Write([]byte("x"))
			if ok {
				flusher.Flush()
			}
			time.Sleep(200 * time.Millisecond) // Drip 1 byte every 200ms
		}
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{
		Timeout: 1,
		Workers: 1,
		DelayMs: 0,
	}
	ep := makeEndpoint(srv.URL)

	start := time.Now()
	findings := CheckHeaders(context.Background(), cfg, ep)
	elapsed := time.Since(start)

	// The check should complete — headers arrive immediately (before body drip)
	if elapsed > 3*time.Second {
		t.Errorf("header check took %v on slow-drip server — should not wait for body", elapsed)
	}
	_ = findings
}
