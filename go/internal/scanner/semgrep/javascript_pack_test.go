package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// The JavaScript/TypeScript taint pack (Task 4.3) and the per-language gate.

// jsTaintRuleID is one taint rule of the JavaScript/TypeScript pack.
const jsTaintRuleID = "js-sqli-taint"

// bundledMetadata is a bundled rule's metadata as semgrep sends it back in
// extra.metadata: the rule's own YAML block, not a stand-in.
func bundledMetadata(t *testing.T, ruleID string) map[string]interface{} {
	t.Helper()
	r, ok := loadAllRules(t)[ruleID]
	if !ok {
		t.Fatalf("rule %s is not in the bundled pack", ruleID)
	}
	meta, ok := r.Raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("rule %s has no metadata block", ruleID)
	}
	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return out
}

// The gate looks a rule up by the id the scanner derives from semgrep's
// check_id, and semgrep namespaces that id by the temporary directory the
// rules were extracted to. The ids below are the shapes semgrep 1.141.0 really
// prints: the macOS one was captured from `semgrep --config
// $TMPDIR/fendix-semgrep-rules-XXXX --json` and the Linux one is /tmp. If
// normalizeCheckID left any of that prefix on, the bundled-spec lookup would
// miss and every JavaScript finding would stay a shim finding however the gate
// is set. The lookup here is the real one, over the embedded pack.
func TestProductionCheckIDOfAJavaScriptTaintRuleReachesTheGate(t *testing.T) {
	meta := bundledMetadata(t, jsTaintRuleID)
	spec, ok := ruleSpecs(jsTaintRuleID)
	if !ok || spec.Mode != "taint" || !reflect.DeepEqual(spec.Languages, []string{"javascript", "typescript"}) {
		t.Fatalf("bundled spec of %s = %+v (found %v); want mode taint, languages [javascript typescript]",
			jsTaintRuleID, spec, ok)
	}

	for _, checkID := range []string{
		"var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T.fendix-semgrep-rules-B2HsHziK." + jsTaintRuleID,
		"private.var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T.fendix-semgrep-rules-1072928901." + jsTaintRuleID,
		"tmp.fendix-semgrep-rules-2173727481." + jsTaintRuleID,
	} {
		t.Run(checkID, func(t *testing.T) {
			if got := normalizeCheckID(checkID); got != jsTaintRuleID {
				t.Fatalf("normalizeCheckID(%q) = %q, want %q", checkID, got, jsTaintRuleID)
			}
			r := semgrepResult{
				CheckID: checkID,
				Path:    "routes/users.js",
				Start:   semgrepLineCol{Line: 9, Col: 3},
				Extra: semgrepExtra{
					Message:  "SQL query built from request input.",
					Severity: "ERROR",
					Lines:    semgrepRedactedLines,
					Metadata: meta,
				},
			}
			mapped := func() evidence.Evidence {
				t.Helper()
				ev, ok := mapResult(&r, "/code")
				if !ok {
					t.Fatal("mapResult dropped the result")
				}
				if ev.RuleID != jsTaintRuleID {
					t.Errorf("RuleID = %q, want %q", ev.RuleID, jsTaintRuleID)
				}
				return ev
			}

			enableReachability(t, "javascript", "typescript")
			requireTaint(t, mapped())

			// The rule also runs on TypeScript files, so JavaScript alone has
			// not met its gate.
			enableReachability(t, "javascript")
			requireShim(t, mapped())

			enableReachability(t)
			requireShim(t, mapped())
		})
	}
}

// The same path end to end: the real scanner extracts the embedded pack to its
// temporary directory, real semgrep runs it over an Express route, and the
// finding that comes back opens the gate once JavaScript and TypeScript are
// enabled.
func TestScanReportsAJavaScriptTaintFindingAsReachable(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(spikeApp), 0o644); err != nil {
		t.Fatal(err)
	}
	find := func() evidence.Evidence {
		t.Helper()
		got, err := Scan(context.Background(), dir)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		for _, f := range got {
			if f.RuleID == jsTaintRuleID {
				if f.Endpoint != "app.js:9" {
					t.Errorf("Endpoint = %q, want app.js:9", f.Endpoint)
				}
				return f
			}
		}
		t.Fatalf("no %s finding in %d findings", jsTaintRuleID, len(got))
		return evidence.Evidence{}
	}

	enableReachability(t)
	requireShim(t, find())

	enableReachability(t, "javascript", "typescript")
	requireTaint(t, find())
}

// The shipped gate, with no test override: JavaScript and TypeScript are
// enabled (Task 4.3), so a match of a taint rule of the pack is reachable and
// a match of one of its shape rules is not, whatever its metadata says.
func TestShippedGateOpensForTheJavaScriptTaintRulesOnly(t *testing.T) {
	result := func(ruleID string) semgrepResult {
		return semgrepResult{
			CheckID: "tmp.fendix-semgrep-rules-1072928901." + ruleID,
			Path:    "routes/users.js",
			Start:   semgrepLineCol{Line: 9, Col: 3},
			Extra: semgrepExtra{
				Message:  "finding",
				Severity: "ERROR",
				Lines:    semgrepRedactedLines,
				Metadata: bundledMetadata(t, ruleID),
			},
		}
	}
	for _, id := range []string{
		"js-sqli-taint", "js-cmdi-taint", "js-ssti-taint", "js-xss-taint", "js-ssrf-taint",
		"js-path-traversal-taint", "js-open-redirect-taint", "js-weak-password-hash-taint",
		"js-jwt-no-verify-taint", "js-weak-random-token-taint",
	} {
		r := result(id)
		ev, ok := mapResult(&r, "/code")
		if !ok {
			t.Fatalf("%s: mapResult dropped the result", id)
		}
		if !ev.Reachable {
			t.Errorf("%s: not reachable with the shipped gate", id)
		}
	}
	for _, id := range []string{
		"js-sqli-sink", "js-cmdi-sink", "js-ssti-sink", "js-xss-sink", "js-open-redirect-sink",
		"js-weak-password-hash-sink", "js-jwt-no-verify-sink",
	} {
		r := result(id)
		r.Extra.Metadata[reachabilityMetadataKey] = reachabilityTaint
		ev, ok := mapResult(&r, "/code")
		if !ok {
			t.Fatalf("%s: mapResult dropped the result", id)
		}
		requireShim(t, ev)
	}
}
