package diagnostic

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2 (OR-13): neighbours of bundle_probes_round6_test.go. Bounds are
// in bytes as well as records, and what a bound leaves out is declared exactly.

func wse2WriteBundle(t *testing.T, records []scanner.ProbeRecord, prep func(b *Bundle)) map[string][]byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	b := New(path, &models.ScanConfig{EnableActive: true, DebugBundlePath: path})
	b.SetProbes(records)
	if prep != nil {
		prep(b)
	}
	if err := b.Write("test"); err != nil {
		t.Fatal(err)
	}
	return readBundle(t, path)
}

func wse2Summary(t *testing.T, entries map[string][]byte) map[string]any {
	t.Helper()
	raw, ok := entries["probes.summary.json"]
	if !ok {
		t.Fatal("the bundle has no probes.summary.json")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A bundle that holds every probe says so, and long target-controlled fields
// are cut.
func TestBundle_WSE2_LongFieldsAreCutAndACompleteLogSaysSo(t *testing.T) {
	long := "http://t.example/" + strings.Repeat("a", 64<<10)
	var recs []scanner.ProbeRecord
	for i := 0; i < 5; i++ {
		recs = append(recs, scanner.ProbeRecord{Endpoint: fmt.Sprintf("%s%d", long, i), Method: "GET", ProbeType: scanner.ProbeSQLi, Status: 200, Payload: strings.Repeat("p", 10<<10)})
	}
	entries := wse2WriteBundle(t, recs, nil)
	for _, line := range strings.Split(strings.TrimSpace(string(entries["probes.jsonl"])), "\n") {
		if len(line) > 4*scanner.ProbeRecordFieldMax {
			t.Errorf("a probe line is %d bytes; the long fields must be cut to %d", len(line), scanner.ProbeRecordFieldMax)
		}
	}
	m := wse2Summary(t, entries)
	if m["truncated"] != false || m["probes_total"] != float64(5) || m["probes_in_bundle"] != float64(5) || m["probes_omitted"] != float64(0) {
		t.Errorf("summary of a complete log: %v", m)
	}
}

// The byte bound binds before the record bound when records are large, and the
// summary counts what was left out.
func TestBundle_WSE2_ByteBoundIsDeclaredWithTheExactCount(t *testing.T) {
	const n = 9_000
	var recs []scanner.ProbeRecord
	pad := strings.Repeat("x", 900)
	for i := 0; i < n; i++ {
		recs = append(recs, scanner.ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/%s/%05d", pad, i), Method: "GET", ProbeType: scanner.ProbeSQLi, Status: 200, Payload: pad})
	}
	entries := wse2WriteBundle(t, recs, nil)
	if got := len(entries["probes.jsonl"]); got > MaxBundleProbeBytes {
		t.Errorf("probes.jsonl is %d bytes, limit %d", got, MaxBundleProbeBytes)
	}
	m := wse2Summary(t, entries)
	in, _ := m["probes_in_bundle"].(float64)
	if m["truncated"] != true || m["probes_total"] != float64(n) || in >= n || m["probes_omitted"] != float64(n)-in {
		t.Errorf("summary: %v, want truncated with probes_omitted = %d - probes_in_bundle", m, n)
	}
	if lines := strings.Count(string(entries["probes.jsonl"]), "\n"); float64(lines) != in {
		t.Errorf("probes.jsonl has %d lines, the summary says %v", lines, in)
	}
}

// debug.log keeps its head and counts the rest.
func TestBundle_WSE2_DebugLogIsBoundedAndSaysWhatItDropped(t *testing.T) {
	entries := wse2WriteBundle(t, nil, func(b *Bundle) {
		h := b.LogHandler(slog.NewTextHandler(io.Discard, nil))
		logger := slog.New(h)
		chunk := strings.Repeat("y", 1<<20)
		for i := 0; i < 20; i++ {
			logger.Debug("noise", "chunk", chunk)
		}
	})
	log := string(entries["debug.log"])
	if len(log) > MaxBundleLogBytes+1024 {
		t.Errorf("debug.log is %d bytes, limit %d", len(log), MaxBundleLogBytes)
	}
	if !strings.Contains(log, "further bytes of this log were not kept") {
		t.Error("debug.log was cut and does not say how much")
	}
}
