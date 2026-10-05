package reporters

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// buildFindings creates n findings with varied severities and sources for benchmark.
func buildFindings(n int) []models.Finding {
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	}
	sources := []models.Source{
		models.SourceBlackbox, models.SourceWhitebox, models.SourceCorrelated,
	}
	findings := make([]models.Finding, n)
	for i := 0; i < n; i++ {
		line := fmt.Sprintf("src/file%d.py:%d", i%20, i+1)
		findings[i] = models.Finding{
			ID:         fmt.Sprintf("SEC-%03d", i+1),
			Title:      fmt.Sprintf("Security Issue #%d", i+1),
			Severity:   severities[i%len(severities)],
			Source:     sources[i%len(sources)],
			Category:   "secrets",
			Endpoint:   fmt.Sprintf("GET /api/resource%d", i%50),
			Evidence:   fmt.Sprintf("Found sensitive data pattern %d in response", i),
			Fix:        "Remove sensitive data from response or use proper access controls",
			References: []string{"CWE-200", "OWASP-A01"},
			Confidence: models.ConfidenceHigh,
			Line:       &line,
		}
	}
	return findings
}

func buildMeta() ScanMetadata {
	return ScanMetadata{
		Target:         "https://api.example.com",
		StartedAt:      time.Now(),
		Duration:       "4.521s",
		Version:        "dev",
		Mode:           "hybrid",
		EndpointsCount: 50,
		ActiveProbes:   false,
		ChecksRun:      []string{"headers", "cors", "auth", "exposure", "secrets", "semgrep"},
	}
}

func BenchmarkRenderJSON_10(b *testing.B) {
	findings := buildFindings(10)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderJSON(&buf, findings, meta)
	}
}

func BenchmarkRenderJSON_100(b *testing.B) {
	findings := buildFindings(100)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderJSON(&buf, findings, meta)
	}
}

func BenchmarkRenderJSON_1000(b *testing.B) {
	findings := buildFindings(1000)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderJSON(&buf, findings, meta)
	}
}

func BenchmarkRenderHTML_10(b *testing.B) {
	findings := buildFindings(10)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderHTML(&buf, findings, meta)
	}
}

func BenchmarkRenderHTML_100(b *testing.B) {
	findings := buildFindings(100)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderHTML(&buf, findings, meta)
	}
}

func BenchmarkRenderSARIF_10(b *testing.B) {
	findings := buildFindings(10)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderSARIF(&buf, findings, meta)
	}
}

func BenchmarkRenderSARIF_100(b *testing.B) {
	findings := buildFindings(100)
	meta := buildMeta()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		RenderSARIF(&buf, findings, meta)
	}
}
