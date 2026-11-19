package engine

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2: OR-13 (R-34) at the orchestrator. The probe pass is summarised
// from scanner.GlobalAuditRecords() (orchestrator.go:306). Once the scan-wide
// log stops retaining every record, that summary must still be exact: the
// orchestrator has to read the streamed aggregate, not count a bounded list.
// Both halves are pinned together so neither change can land without the other.
func TestSummarizeCheckPhase_OR13_ExactCountsFromABoundedLog(t *testing.T) {
	const n = 100_000
	// The scan-wide log captures os.Stderr when it is created; point it at the
	// null device so 100,000 probe lines do not flood the test output.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	saved := os.Stderr
	os.Stderr = null
	scanner.ResetGlobalAuditLog()
	os.Stderr = saved
	defer scanner.ResetGlobalAuditLog()

	log := scanner.GlobalProbeLog()
	for i := 0; i < n; i++ {
		status := 403
		if i%50 == 0 {
			status = 200
		}
		log.Record(scanner.ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/e/%06d?id=1", i/4), Method: "GET",
			ProbeType: scanner.ProbeSQLi, Parameter: "id", Payload: "x", Status: status, Duration: "3ms"})
	}
	if got := len(scanner.GlobalAuditRecords()); got > 10_000 {
		t.Errorf("the scan-wide log retains %d records for %d probes; R-34 needs a fixed bound", got, n)
	}
	phase := summarizeCheckPhase(context.Background(), scanner.GlobalAuditRecords(), 0)
	if p := phase.Probes; p.Attempted != n || p.Evaluated != n/50 || p.Gated.Total != n-n/50 {
		t.Errorf("probe pass summary not exact: attempted %d evaluated %d gated %d, want %d/%d/%d", p.Attempted, p.Evaluated, p.Gated.Total, n, n/50, n-n/50)
	}
}
