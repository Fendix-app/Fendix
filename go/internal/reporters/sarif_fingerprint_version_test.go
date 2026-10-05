package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// §8 — the fingerprint SCHEME is versioned in the key, so a consumer that
// baselined on v1 hashes never silently matches them against v2 hashes. The
// key must name the algorithm this build actually produces.
func TestPartialFingerprintKeyNamesTheAlgorithmInUse(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "a1b2c3", Title: "Missing auth",
		Severity: models.SeverityHigh, Source: models.SourceBlackbox,
		Category: "auth", Endpoint: "GET /api/users",
	}
	meta := ScanMetadata{Version: "test", FingerprintAlgorithm: models.FingerprintAlgorithm}
	if err := RenderSARIF(&buf, []models.Finding{f}, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	fps := log.Runs[0].Results[0].PartialFingerprints
	if _, ok := fps[models.FingerprintAlgorithm]; !ok {
		t.Errorf("no key for the algorithm this build produces (%s); got %v",
			models.FingerprintAlgorithm, fps)
	}
	if _, ok := fps["fendix/v1"]; ok {
		t.Error("v2 identities are still published under the v1 key — a v1 baseline would match them by mistake")
	}
}

// SARIF distinguishes `fingerprints` (the tool asserts these are THE identity)
// from `partialFingerprints` (inputs a consumer may combine for baseline
// matching). Fendix's is a complete, self-sufficient identity, but GitHub Code
// Scanning consumes partialFingerprints for alert matching and ignores
// fingerprints — so partialFingerprints is where it has to be to do its job.
func TestFingerprintUsesThePartialFingerprintsMechanism(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "a1b2c3", Title: "x",
		Severity: models.SeverityLow, Category: "auth", Endpoint: "GET /x",
	}
	if err := RenderSARIF(&buf, []models.Finding{f}, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	res := raw["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	if _, ok := res["partialFingerprints"]; !ok {
		t.Error("identity is not published where GitHub reads it")
	}
}

// A fingerprint's key must name the algorithm that PRODUCED the value, not the
// algorithm this build happens to compute.
//
// `fendix report --input` re-renders an ARCHIVED report: the findings, and
// their fingerprints, come from the file. Keying those off a build-time
// constant labels a v1 value `fendix/v2`, so a v2 consumer matches it against
// real v2 identities — the wrong namespace, silently. That is the same
// "one key, two meanings" hazard the key was versioned to prevent, arriving
// from the other direction.
func TestFingerprintKeyNamesTheAlgorithmThatProducedTheValue(t *testing.T) {
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "a1b2c3", Title: "Missing auth",
		Severity: models.SeverityHigh, Source: models.SourceBlackbox,
		Category: "auth", Endpoint: "GET /api/users",
	}

	for _, tc := range []struct{ name, announced, wantKey string }{
		{"a v2 report keeps the v2 key", "fendix/v2", "fendix/v2"},
		{"a report that announces v1 keeps the v1 key", "fendix/v1", "fendix/v1"},
		{"an archived report that announces nothing is v1", "", "fendix/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			meta := ScanMetadata{Version: "test", FingerprintAlgorithm: tc.announced}
			if err := RenderSARIF(&buf, []models.Finding{f}, meta); err != nil {
				t.Fatalf("RenderSARIF: %v", err)
			}
			var log SARIFLog
			if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			fps := log.Runs[0].Results[0].PartialFingerprints
			if got := fps[tc.wantKey]; got != "a1b2c3" {
				t.Errorf("no value under %q; got %v", tc.wantKey, fps)
			}
			if len(fps) != 1 {
				t.Errorf("expected exactly one key, got %v", fps)
			}
		})
	}
}

// A live scan must announce the algorithm it actually used, or its own SARIF
// falls back to the archived-report default.
func TestLiveScanMetadataAnnouncesTheFingerprintAlgorithm(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{ID: "SEC-001", Title: "x", Category: "auth", Endpoint: "GET /x"}
	if err := RenderJSON(&buf, []models.Finding{f}, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Metadata ScanMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Metadata.FingerprintAlgorithm != models.FingerprintAlgorithm {
		t.Errorf("fingerprint_algorithm = %q", doc.Metadata.FingerprintAlgorithm)
	}
}
