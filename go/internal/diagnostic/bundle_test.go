package diagnostic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

func TestBundle_NilPathDisabled(t *testing.T) {
	b := New("", &models.ScanConfig{})
	if b.Enabled() {
		t.Fatal("empty path should produce a disabled bundle")
	}

	// All setters and Write must be no-ops on a disabled bundle.
	b.SetFindings(struct{}{})
	b.SetMetadata(struct{}{})
	b.SetProbes(nil)
	b.SetPythonVersion("3.13")
	if err := b.Write("dev"); err != nil {
		t.Fatalf("Write on disabled bundle should be no-op: %v", err)
	}
}

func TestBundle_LogHandlerReturnsBaseWhenDisabled(t *testing.T) {
	b := New("", &models.ScanConfig{})
	base := slog.NewTextHandler(io.Discard, nil)
	got := b.LogHandler(base)
	if got != base {
		t.Errorf("disabled bundle should return base handler unchanged; got %T", got)
	}
}

func TestBundle_WriteProducesExpectedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")

	cfg := &models.ScanConfig{
		URL: "https://example.com",
		Auth: &models.AuthContext{
			Type:   "bearer",
			Header: "Authorization",
			Value:  "Bearer SUPER_SECRET_TOKEN",
		},
	}
	b := New(path, cfg)

	// Capture some debug log content.
	logger := slog.New(b.LogHandler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))
	logger.Debug("debug record", "secret_field", "Bearer SUPER_SECRET_TOKEN")
	logger.Info("info record", "key", "v")

	b.SetMetadata(map[string]any{"target": "https://example.com", "duration": "1s"})
	b.SetFindings([]map[string]any{{"id": "SEC-001"}})
	b.SetPythonVersion("3.13.0")

	if err := b.Write("0.5.0"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	entries := readBundle(t, path)
	required := []string{"README.md", "config.json", "environment.json", "metadata.json", "findings.json", "debug.log"}
	for _, name := range required {
		if _, ok := entries[name]; !ok {
			t.Errorf("missing entry %q; got %v", name, keys(entries))
		}
	}
	if _, ok := entries["probes.jsonl"]; ok {
		t.Errorf("probes.jsonl should be absent when --enable-active is off")
	}
}

func TestBundle_RedactsAuthValueFromConfigAndLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")

	const secret = "Bearer s3cr3t-tok3n-do-not-leak"
	cfg := &models.ScanConfig{
		Auth: &models.AuthContext{
			Type:   "bearer",
			Header: "Authorization",
			Value:  secret,
		},
		AuthUser2: &models.AuthContext{
			Type:   "bearer",
			Header: "Authorization",
			Value:  "Bearer second-user-token",
		},
	}
	b := New(path, cfg)

	logger := slog.New(b.LogHandler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))
	logger.Debug("a record that mentions the secret", "auth", secret)
	logger.Debug("bare token also leaked", "raw", "s3cr3t-tok3n-do-not-leak")

	b.SetFindings([]map[string]any{{"evidence": "no secrets here"}})
	if err := b.Write("dev"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	entries := readBundle(t, path)
	for name, body := range entries {
		if strings.Contains(string(body), "s3cr3t-tok3n-do-not-leak") {
			t.Errorf("entry %q leaked the bare secret token", name)
		}
		if strings.Contains(string(body), "Bearer s3cr3t-tok3n-do-not-leak") {
			t.Errorf("entry %q leaked the full Bearer token", name)
		}
	}

	// config.json must show [REDACTED] for the auth value but preserve
	// type/header for diagnosis.
	var cfgOut map[string]any
	if err := json.Unmarshal(entries["config.json"], &cfgOut); err != nil {
		t.Fatalf("invalid config.json: %v", err)
	}
	auth, ok := cfgOut["auth"].(map[string]any)
	if !ok {
		t.Fatalf("config.json missing auth object: %v", cfgOut)
	}
	if auth["value"] != "[REDACTED]" {
		t.Errorf("expected auth.value=[REDACTED]; got %v", auth["value"])
	}
	if auth["type"] != "bearer" {
		t.Errorf("expected auth.type to be preserved; got %v", auth["type"])
	}
	if auth["header"] != "Authorization" {
		t.Errorf("expected auth.header to be preserved; got %v", auth["header"])
	}
}

func TestBundle_EnableActiveIncludesProbesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")

	cfg := &models.ScanConfig{
		EnableActive: true,
	}
	b := New(path, cfg)
	b.SetProbes([]scanner.ProbeRecord{
		{
			Timestamp: time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC),
			Endpoint:  "https://example.com/api",
			ProbeType: scanner.ProbeSQLi,
			Payload:   "' OR 1=1--",
			Parameter: "id",
			Method:    "GET",
			Status:    200,
			Duration:  "5ms",
			Finding:   false,
		},
	})

	if err := b.Write("dev"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	entries := readBundle(t, path)
	probes, ok := entries["probes.jsonl"]
	if !ok {
		t.Fatal("probes.jsonl missing despite EnableActive=true")
	}
	if !strings.Contains(string(probes), `"endpoint":"https://example.com/api"`) {
		t.Errorf("probes.jsonl missing endpoint field: %s", probes)
	}
	if !strings.Contains(string(probes), `"probe_type":"sqli"`) {
		t.Errorf("probes.jsonl missing probe_type field: %s", probes)
	}
}

func TestBundle_EnableActiveButNoProbesStillEmitsFile(t *testing.T) {
	// An empty probes.jsonl is itself signal — confirms active probing was
	// requested but no probes were sent (e.g. early exit, no targets).
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	b := New(path, &models.ScanConfig{EnableActive: true})
	if err := b.Write("dev"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	entries := readBundle(t, path)
	body, ok := entries["probes.jsonl"]
	if !ok {
		t.Fatal("probes.jsonl missing")
	}
	if len(body) != 0 {
		t.Errorf("expected empty probes.jsonl; got %q", body)
	}
}

func TestBundle_EnvironmentRecordsRuntimeFacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	b := New(path, &models.ScanConfig{})
	b.SetPythonVersion("3.13.1")
	if err := b.Write("v0.5.0"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	entries := readBundle(t, path)
	var env map[string]string
	if err := json.Unmarshal(entries["environment.json"], &env); err != nil {
		t.Fatalf("invalid environment.json: %v", err)
	}
	for _, key := range []string{"fendix_version", "go_version", "goos", "goarch", "python_version", "captured_at"} {
		if env[key] == "" {
			t.Errorf("environment.json missing or empty key %q; got %v", key, env)
		}
	}
	if env["fendix_version"] != "v0.5.0" {
		t.Errorf("expected fendix_version=v0.5.0; got %q", env["fendix_version"])
	}
	if env["python_version"] != "3.13.1" {
		t.Errorf("expected python_version=3.13.1; got %q", env["python_version"])
	}
}

func TestBundle_WriteFailsOnUnwritablePath(t *testing.T) {
	// Path inside a non-existent directory must surface an error rather
	// than silently fail (matches the actionable-error guidance in TASK-078).
	b := New("/nonexistent-dir-asdf/bundle.tar.gz", &models.ScanConfig{})
	if !b.Enabled() {
		t.Fatal("bundle should be enabled")
	}
	if err := b.Write("dev"); err == nil {
		t.Fatal("expected an error when path is unwritable")
	}
}

// readBundle decompresses a .tar.gz and returns name → body for every entry.
func readBundle(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			t.Fatalf("tar read body for %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = buf.Bytes()
	}
	return out
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
