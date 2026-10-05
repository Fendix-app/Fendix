package reporters

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// A corroborated finding must carry its independent-tool provenance into
// SARIF, so re-exporting into GitHub code scanning does not silently reduce
// "two engines agreed" to "fendix scored this highly".
func TestSARIFCarriesCorroboratingTools(t *testing.T) {
	f := models.Finding{
		ID: "SEC-001", Title: "SQL injection", Category: "injection",
		Endpoint: "app/views.py:100", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		CrossToolCorroborated: true,
		CorroboratingTools:    []string{"codeql", "semgrep"},
	}
	props := sarifResultProperties(f)
	if props == nil {
		t.Fatal("a corroborated finding must produce result properties")
	}
	if strings.Join(props.CorroboratingTools, ",") != "codeql,semgrep" {
		t.Fatalf("CorroboratingTools = %v, want [codeql semgrep]", props.CorroboratingTools)
	}
}

func TestSARIFOmitsCorroborationWhenAbsent(t *testing.T) {
	f := models.Finding{
		ID: "SEC-002", Title: "Missing header", Category: "headers",
		Endpoint: "GET /", Severity: models.SeverityLow,
		Source: models.SourceBlackbox, Evidence: "no CSP",
	}
	props := sarifResultProperties(f)
	if props != nil && len(props.CorroboratingTools) != 0 {
		t.Fatalf("uncorroborated findings must omit the tools, got %v", props.CorroboratingTools)
	}
}
