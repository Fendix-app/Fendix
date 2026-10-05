package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// generateFindingJSON creates a valid finding JSON line for benchmarking.
func generateFindingJSON(i int) string {
	return fmt.Sprintf(
		`{"title":"Finding %d","severity":"HIGH","source":"whitebox","category":"secrets","endpoint":"src/file%d.py:%d","evidence":"API_KEY = 'sk-live-%d'","fix":"Use env var","references":["CWE-798"],"confidence":"HIGH","line":"src/file%d.py:%d"}`,
		i, i%100, i, i, i%100, i,
	)
}

// buildFindingStream creates a newline-delimited JSON stream of n findings
// with a done message at the end.
func buildFindingStream(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(generateFindingJSON(i))
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf(`{"done":true,"total":%d}`, n))
	b.WriteByte('\n')
	return b.String()
}

func BenchmarkReadFindings_10(b *testing.B) {
	stream := buildFindingStream(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readFindings(strings.NewReader(stream))
	}
}

func BenchmarkReadFindings_100(b *testing.B) {
	stream := buildFindingStream(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readFindings(strings.NewReader(stream))
	}
}

func BenchmarkReadFindings_1000(b *testing.B) {
	stream := buildFindingStream(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readFindings(strings.NewReader(stream))
	}
}

// buildMixedFindings creates n findings split between blackbox and whitebox
// with overlapping endpoints for correlation testing.
func buildMixedFindings(n int) []models.Finding {
	findings := make([]models.Finding, 0, n)
	for i := 0; i < n/2; i++ {
		findings = append(findings, models.Finding{
			Title:      fmt.Sprintf("BB Finding %d", i),
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   fmt.Sprintf("GET /api/v1/resource%d", i%50),
			Evidence:   "HTTP 200 without auth",
			Fix:        "Require authentication",
			References: []string{"CWE-306"},
			Confidence: models.ConfidenceHigh,
		})
	}
	for i := 0; i < n/2; i++ {
		line := fmt.Sprintf("src/routes/resource%d.py:%d", i%50, i+10)
		findings = append(findings, models.Finding{
			Title:      fmt.Sprintf("WB Finding %d", i),
			Severity:   models.SeverityMedium,
			Source:     models.SourceWhitebox,
			Category:   "auth",
			Endpoint:   line,
			Evidence:   "Missing @login_required",
			Fix:        "Add authentication decorator",
			References: []string{"CWE-306"},
			Confidence: models.ConfidenceMedium,
			Line:       &line,
		})
	}
	return findings
}

func BenchmarkCorrelate_20(b *testing.B) {
	findings := buildMixedFindings(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Correlate(findings)
	}
}

func BenchmarkCorrelate_100(b *testing.B) {
	findings := buildMixedFindings(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Correlate(findings)
	}
}

func BenchmarkCorrelate_500(b *testing.B) {
	findings := buildMixedFindings(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Correlate(findings)
	}
}

func BenchmarkNormalizeEndpoint(b *testing.B) {
	endpoints := []string{
		"https://api.example.com/api/v1/users?page=1",
		"GET /api/v1/users",
		"src/routes/users.py:42",
		"/api/v2/admin/settings",
		"http://localhost:8080/health",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeEndpoint(endpoints[i%len(endpoints)])
	}
}
