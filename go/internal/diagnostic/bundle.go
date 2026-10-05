package diagnostic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// bundleReadme is the top-level explainer included as README.md in every
// bundle. Surfaces (a) what's in the bundle, (b) what was redacted, (c) how
// to share it. Updated when entries are added.
const bundleReadme = `# Fendix Debug Bundle

This archive captures the runtime state of a single fendix scan. It is
intended to be attached to a bug report so maintainers can reproduce or
diagnose the issue without re-running the scan.

## Contents

- README.md           — this file
- config.json         — scan configuration with credentials redacted
- environment.json    — fendix version, OS, Go runtime, Python version
- metadata.json       — scan metadata (target, duration, mode, counts)
- findings.json       — the scan's findings, post-sanitization
- probes.jsonl        — active probe audit log (only when --enable-active)
- debug.log           — buffered DEBUG-level slog stream from the scan

## Redaction

The following are replaced with [REDACTED] before being written to this
archive:

- The --auth credential value (Authorization header / api-key / cookie / basic)
- The --auth-user2 credential value (used by IDOR checks)
- Any literal occurrence of either credential anywhere inside the slog stream
  or finding evidence

The auth header NAME (e.g. "Authorization", "X-Api-Key") is preserved
because it is not a secret and is useful for diagnosis.

## What is NOT redacted

- File paths from --code, --spec, --ignore, --output
- Endpoint URLs, response status codes, finding evidence (already sanitized
  by the scan pipeline before reaching this bundle)
- Probe payloads (these are the canned strings fendix sends; not secrets)

If you scan a target whose URL itself contains credentials, the URL is not
auto-redacted. Inspect config.json before sharing.

## Sharing

Attach the .tar.gz to a GitHub issue at the fendix repository, or email it
to the maintainer listed in SECURITY.md.
`

// Bundle aggregates per-scan diagnostic state and writes a tar.gz archive
// at Write() time. A nil receiver is safe: every method becomes a no-op so
// orchestrator wiring can treat "no --debug-bundle set" as the default.
type Bundle struct {
	enabled bool
	path    string

	mu        sync.Mutex
	cfg       *models.ScanConfig
	meta      json.RawMessage
	findings  json.RawMessage
	probes    []scanner.ProbeRecord
	pythonVer string

	// logMu guards logBuf only. Kept separate from mu so a late slog write
	// from a goroutine that didn't drain before the orchestrator called
	// Write() can't deadlock against the metadata-write critical section.
	logMu  sync.Mutex
	logBuf bytes.Buffer

	// teeHandler captures DEBUG-level slog records into logBuf alongside
	// whatever the user's existing slog handler does. nil when disabled.
	teeHandler slog.Handler
}

// New returns a Bundle. If path is empty, the returned Bundle is disabled
// — every method is a no-op so the orchestrator can call them
// unconditionally without paying for the work.
func New(path string, cfg *models.ScanConfig) *Bundle {
	if path == "" {
		return &Bundle{}
	}
	b := &Bundle{
		enabled: true,
		path:    path,
		cfg:     cfg,
	}
	b.teeHandler = newBufferHandler(&b.logBuf, &b.logMu)
	return b
}

// Enabled reports whether the bundle will be written. When false, every
// method on Bundle is a no-op.
func (b *Bundle) Enabled() bool {
	return b != nil && b.enabled
}

// LogHandler returns a slog.Handler that fans records out to the user's
// existing handler `base` AND captures DEBUG-and-above records into the
// bundle's buffer. The caller is expected to install this handler as the
// process default for the duration of the scan, then restore the previous
// default afterwards.
//
// When disabled, returns base unchanged.
func (b *Bundle) LogHandler(base slog.Handler) slog.Handler {
	if !b.Enabled() || b.teeHandler == nil {
		return base
	}
	return &fanoutHandler{handlers: []slog.Handler{base, b.teeHandler}}
}

// SetMetadata stores an opaque JSON-marshallable scan-metadata value. The
// orchestrator passes the same reporters.ScanMetadata it gives the JSON
// reporter so the bundle's metadata.json matches the report.
func (b *Bundle) SetMetadata(meta any) {
	if !b.Enabled() {
		return
	}
	if data, err := json.MarshalIndent(meta, "", "  "); err == nil {
		b.mu.Lock()
		b.meta = data
		b.mu.Unlock()
	}
}

// SetFindings stores a JSON-marshallable findings slice — typically the
// post-sanitization slice the orchestrator passes to the reporters.
func (b *Bundle) SetFindings(findings any) {
	if !b.Enabled() {
		return
	}
	if data, err := json.MarshalIndent(findings, "", "  "); err == nil {
		b.mu.Lock()
		b.findings = data
		b.mu.Unlock()
	}
}

// SetProbes stores the active-probe audit log. Empty when --enable-active
// was not set.
func (b *Bundle) SetProbes(records []scanner.ProbeRecord) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	b.probes = records
	b.mu.Unlock()
}

// SetPythonVersion stores the resolved Python interpreter version string,
// or empty if the white-box engine wasn't run.
func (b *Bundle) SetPythonVersion(v string) {
	if !b.Enabled() {
		return
	}
	b.mu.Lock()
	b.pythonVer = v
	b.mu.Unlock()
}

// Write serializes all collected state to a tar.gz at the configured path.
// Returns nil when disabled. Auth credential values are redacted from
// debug.log entries that happened to log the secret; config.json's auth
// value is always [REDACTED].
func (b *Bundle) Write(fendixVersion string) error {
	if !b.Enabled() {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	secrets := secretsFrom(b.cfg)

	f, err := os.Create(b.path)
	if err != nil {
		return fmt.Errorf("creating debug bundle %s: %w", b.path, err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	now := time.Now().UTC()

	if err := writeEntry(tw, "README.md", []byte(bundleReadme), now); err != nil {
		return err
	}

	configBytes, err := json.MarshalIndent(newRedactedConfig(b.cfg), "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling redacted config: %w", err)
	}
	if err := writeEntry(tw, "config.json", configBytes, now); err != nil {
		return err
	}

	envBytes, err := json.MarshalIndent(map[string]string{
		"fendix_version": fendixVersion,
		"go_version":     runtime.Version(),
		"goos":           runtime.GOOS,
		"goarch":         runtime.GOARCH,
		"python_version": b.pythonVer,
		"captured_at":    now.Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling environment: %w", err)
	}
	if err := writeEntry(tw, "environment.json", envBytes, now); err != nil {
		return err
	}

	if len(b.meta) > 0 {
		if err := writeEntry(tw, "metadata.json", b.meta, now); err != nil {
			return err
		}
	}

	if len(b.findings) > 0 {
		if err := writeEntry(tw, "findings.json", b.findings, now); err != nil {
			return err
		}
	}

	// probes.jsonl is one JSON object per line; matches the format the
	// audit log writes to stderr at scan time. Always written when
	// --enable-active was set, even when the scan recorded zero probes
	// (an empty file is itself signal — confirms active probing was on).
	if b.cfg != nil && b.cfg.EnableActive {
		var pbuf bytes.Buffer
		// Stable order on emit so the bundle is reproducible across runs
		// of the same target. Audit records are appended in scan order
		// today, but a future parallelization could reorder them.
		records := append([]scanner.ProbeRecord(nil), b.probes...)
		sort.SliceStable(records, func(i, j int) bool {
			if !records[i].Timestamp.Equal(records[j].Timestamp) {
				return records[i].Timestamp.Before(records[j].Timestamp)
			}
			if records[i].Endpoint != records[j].Endpoint {
				return records[i].Endpoint < records[j].Endpoint
			}
			return records[i].Parameter < records[j].Parameter
		})
		for _, r := range records {
			line, err := json.Marshal(r)
			if err != nil {
				return fmt.Errorf("marshalling probe record: %w", err)
			}
			pbuf.Write(line)
			pbuf.WriteByte('\n')
		}
		if err := writeEntry(tw, "probes.jsonl", pbuf.Bytes(), now); err != nil {
			return err
		}
	}

	b.logMu.Lock()
	logText := redactSecrets(b.logBuf.String(), secrets)
	b.logMu.Unlock()
	if err := writeEntry(tw, "debug.log", []byte(logText), now); err != nil {
		return err
	}

	return nil
}

// writeEntry writes a single regular file entry to the tar archive. Mode
// 0o644, owned by uid 0 / gid 0 (a published bundle has no useful
// attribution) — keeps the tar reproducible.
func writeEntry(tw *tar.Writer, name string, data []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: modTime,
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing tar header for %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("writing tar body for %s: %w", name, err)
	}
	return nil
}

// fanoutHandler delivers each slog record to every wrapped handler in turn.
// Used to tee the user's stderr handler with the bundle's buffer handler
// without changing what the user sees on stderr.
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clones := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		clones[i] = h.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: clones}
}

func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	clones := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		clones[i] = h.WithGroup(name)
	}
	return &fanoutHandler{handlers: clones}
}

// newBufferHandler returns a slog text handler that writes DEBUG-level and
// above records into buf, locked under mu so concurrent writers don't
// interleave bytes mid-record.
func newBufferHandler(buf *bytes.Buffer, mu *sync.Mutex) slog.Handler {
	return slog.NewTextHandler(&lockedWriter{buf: buf, mu: mu}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
}

// lockedWriter serializes concurrent writes to a bytes.Buffer through the
// shared mutex. Without this the worker pool can interleave bytes from two
// log records during the same scan.
type lockedWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
