package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// §8/§23 — the fingerprint algorithm is part of the report contract, and it
// changed. A consumer holding a saved baseline or a `.fendix-ignore`
// `fingerprint:` rule written under v1 must regenerate it: v1 and v2 share no
// hash, so a stale baseline silently matches nothing and every finding reads
// as new.
//
// "Silently matches nothing" is exactly the failure schema_version exists to
// prevent, so this is the bump the field's own rule asks for — a change a
// consumer must react to, as distinct from the purely additive keys that
// deliberately do not bump it.
func TestSchemaVersionRecordsTheFingerprintBreak(t *testing.T) {
	if SchemaVersion < 2 {
		t.Errorf("SchemaVersion is %d: the fingerprint algorithm changed and every stored "+
			"baseline must be regenerated — consumers need that signal", SchemaVersion)
	}
}

// A version number says "something changed"; it does not say WHAT the
// fingerprints in this report are. The algorithm names itself, so a consumer
// comparing two archived reports can tell whether their fingerprints are even
// comparable. SARIF gets this from the partialFingerprints key; JSON needs
// its own.
func TestReportNamesTheFingerprintAlgorithmItUsed(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "abc", Title: "x", Category: "auth",
		Endpoint: "GET /x", Severity: models.SeverityLow,
	}
	if err := RenderJSON(&buf, []models.Finding{f}, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Metadata struct {
			SchemaVersion        int    `json:"schema_version"`
			FingerprintAlgorithm string `json:"fingerprint_algorithm"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Metadata.FingerprintAlgorithm != models.FingerprintAlgorithm {
		t.Errorf("fingerprint_algorithm = %q, want %q",
			doc.Metadata.FingerprintAlgorithm, models.FingerprintAlgorithm)
	}
}
