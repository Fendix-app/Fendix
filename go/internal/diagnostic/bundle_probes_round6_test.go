package diagnostic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2: OR-50 / OR-13 (R-34). The --debug-bundle copies the whole
// scan-wide probe log (bundle.go:159, fed by scanner.GlobalAuditRecords). Once
// the log is bounded (OR-27), the bundle holds a subset; it must say so, with
// the exact total, rather than present a partial log as the whole one. And it
// must not itself hold an unbounded copy.
func TestBundle_OR13_ProbesAreBoundedAndATruncationIsDeclared(t *testing.T) {
	const n = 20_000
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	saved := os.Stderr
	os.Stderr = null // the scan-wide log captures os.Stderr when created
	scanner.ResetGlobalAuditLog()
	os.Stderr = saved
	defer scanner.ResetGlobalAuditLog()
	log := scanner.GlobalProbeLog()
	for i := 0; i < n; i++ {
		log.Record(scanner.ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/e/%06d", i), Method: "GET", ProbeType: scanner.ProbeSQLi, Status: 403})
	}

	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	b := New(path, &models.ScanConfig{EnableActive: true, DebugBundlePath: path})
	b.SetProbes(scanner.GlobalAuditRecords()) // as orchestrator.go:870 does
	if err := b.Write("test"); err != nil {
		t.Fatal(err)
	}
	entries := readBundle(t, path)
	lines := strings.Count(string(entries["probes.jsonl"]), "\n")
	if lines > 10_000 {
		t.Errorf("the bundle holds %d probe records for %d probes; it must hold a bounded number (R-34)", lines, n)
	}
	if lines < n {
		declared := false
		for name, body := range entries {
			s := string(body)
			if strings.Contains(s, "truncated") && strings.Contains(s, fmt.Sprint(n)) {
				declared = true
				_ = name
			}
		}
		if !declared {
			t.Errorf("the bundle holds %d of %d probe records and does not say it is truncated, with the exact total", lines, n)
		}
	}
}
