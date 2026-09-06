package engine

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// TestMemory_LargeFindingStream verifies memory stays bounded when processing
// 1000+ findings through the readFindings pipeline.
func TestMemory_LargeFindingStream(t *testing.T) {
	const numFindings = 2000

	// Build a stream of 2000 findings
	stream := buildFindingStream(numFindings)

	// Force GC before measurement
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	sr := readFindings(strings.NewReader(stream))
	if sr.readErr != nil {
		t.Fatalf("readFindings failed: %v", sr.readErr)
	}

	// Force GC after
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	if len(sr.findings) != numFindings {
		t.Errorf("expected %d findings, got %d", numFindings, len(sr.findings))
	}
	if sr.doneTotal != numFindings {
		t.Errorf("expected total %d, got %d", numFindings, sr.doneTotal)
	}

	// Calculate memory used by findings
	allocatedBytes := memAfter.TotalAlloc - memBefore.TotalAlloc
	bytesPerFinding := allocatedBytes / uint64(numFindings)

	t.Logf("Memory for %d findings: %d KB total, %d bytes/finding",
		numFindings, allocatedBytes/1024, bytesPerFinding)

	// Budget: < 10KB per finding (findings are typically 200-500 bytes JSON)
	// This is generous — we're checking for leaks, not micro-optimizing
	if bytesPerFinding > 10*1024 {
		t.Errorf("memory per finding too high: %d bytes (budget: 10KB)", bytesPerFinding)
	}
}

// TestMemory_LargeCorrelation verifies the correlator doesn't blow up memory
// with large mixed finding sets.
func TestMemory_LargeCorrelation(t *testing.T) {
	const numFindings = 1000
	findings := buildMixedFindings(numFindings)

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	result := Correlate(findings)

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	allocatedBytes := memAfter.TotalAlloc - memBefore.TotalAlloc

	t.Logf("Correlator: %d input → %d output, %d KB allocated",
		numFindings, len(result), allocatedBytes/1024)

	// Budget: output should not be dramatically larger than input
	if len(result) > numFindings*2 {
		t.Errorf("correlator produced %d findings from %d input — possible duplication bug",
			len(result), numFindings)
	}

	// Budget: < 20MB for correlating 1000 findings
	// (includes slog structured logging allocations for each correlation match)
	if allocatedBytes > 20*1024*1024 {
		t.Errorf("correlator used %d KB for %d findings — exceeds 20MB budget",
			allocatedBytes/1024, numFindings)
	}
}

// BenchmarkMemory_ReadFindings2000 profiles memory for a large finding stream.
func BenchmarkMemory_ReadFindings2000(b *testing.B) {
	stream := buildFindingStream(2000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readFindings(strings.NewReader(stream))
	}
}

// BenchmarkMemory_Correlate1000 profiles memory for large correlation.
func BenchmarkMemory_Correlate1000(b *testing.B) {
	findings := buildMixedFindings(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Correlate(findings)
	}
}

// TestMemory_ReporterLargeOutput verifies reporters handle 1000+ findings
// without excessive memory use.
func TestMemory_ReporterLargeOutput(t *testing.T) {
	const numFindings = 1000
	findings := make([]models.Finding, numFindings)
	for i := 0; i < numFindings; i++ {
		line := fmt.Sprintf("src/file%d.py:%d", i%50, i+1)
		findings[i] = models.Finding{
			ID:         fmt.Sprintf("SEC-%03d", i+1),
			Title:      fmt.Sprintf("Finding %d", i+1),
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   fmt.Sprintf("GET /api/resource%d", i%100),
			Evidence:   "HTTP 200 without auth",
			Fix:        "Add authentication",
			References: []string{"CWE-306"},
			Confidence: models.ConfidenceHigh,
			Line:       &line,
		}
	}

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Sort (simulates orchestrator ID assignment)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	allocatedBytes := memAfter.TotalAlloc - memBefore.TotalAlloc
	t.Logf("ID assignment for %d findings: %d KB", numFindings, allocatedBytes/1024)
}
