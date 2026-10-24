package engine

import (
	"slices"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The Python engine's JavaScript/TypeScript pattern checks (JS_EVAL,
// JS_INNER_HTML, JS_DOCUMENT_WRITE, JS_SQL_TEMPLATE) used to emit no rule_id.
// Identity then fell back to the finding's id: ruleIdentity accepts a
// "SEC-"-prefixed id that is not the orchestrator's positional SEC-NNN counter,
// and StampIdentity runs BEFORE the positional ids are assigned, so the rule
// component of every such finding's fingerprint has always been
// rule=SEC-JS_SQL_TEMPLATE (and so on).
//
// These findings now carry an explicit rule_id. It MUST be that same string:
// the fingerprint is the key a baseline, a `.fendix-ignore` `fingerprint:` rule
// and a Code Scanning alert are filed under, so any other value would
// re-identify every JS-pattern finding an existing consumer already tracks.
//
// recordedJSSQLFingerprint was read from a real run of the engine, built from
// the commit BEFORE the rule_id was added, over a one-line app.ts:
//
//	const r = await pool.query(`SELECT * FROM u WHERE n = '${name}'`);
const (
	recordedJSSQLFingerprint   = "1ab76009f62b49ad02f0a4860a88948da8dea0f5"
	recordedJSSQLFingerprintV1 = "9e10c186bad1b54d22bf39aeeb0cb0d741e0b7ca"

	// What the Python engine put on the wire for that file, before and after.
	// The two lines differ only by the rule_id key.
	jsSQLLineBefore = `{"id": "SEC-JS_SQL_TEMPLATE", "title": "SQL query built via template literal — injection risk", "severity": "HIGH", "source": "whitebox", "category": "injection", "endpoint": "app.ts:1", "evidence": "const r = await pool.query(` + "`" + `SELECT * FROM u WHERE n = '${name}'` + "`" + `);", "fix": "Use parameterized queries or an ORM instead of building SQL with template literals.", "references": ["CWE-89"], "confidence": "HIGH", "line": "app.ts:1"}`
	jsSQLLineAfter  = `{"id": "SEC-JS_SQL_TEMPLATE", "rule_id": "SEC-JS_SQL_TEMPLATE", "title": "SQL query built via template literal — injection risk", "severity": "HIGH", "source": "whitebox", "category": "injection", "endpoint": "app.ts:1", "evidence": "const r = await pool.query(` + "`" + `SELECT * FROM u WHERE n = '${name}'` + "`" + `);", "fix": "Use parameterized queries or an ORM instead of building SQL with template literals.", "references": ["CWE-89"], "confidence": "HIGH", "line": "app.ts:1"}`
)

// stampedFromWire parses one engine stdout line exactly as the spawner does
// and stamps identity exactly as the orchestrator does.
func stampedFromWire(t *testing.T, line string) models.Finding {
	t.Helper()
	sr := readFindings(strings.NewReader(line + "\n" + `{"done":true,"total":1}` + "\n"))
	if sr.readErr != nil {
		t.Fatalf("reading engine stream: %v", sr.readErr)
	}
	if len(sr.findings) != 1 {
		t.Fatalf("want 1 finding from the stream, got %d", len(sr.findings))
	}
	f := sr.findings[0]
	models.StampIdentity(&f)
	return f
}

func TestJSPatternFingerprintUnchanged(t *testing.T) {
	t.Run("recorded wire line reproduces the recorded fingerprint", func(t *testing.T) {
		// Proves the fixture is faithful to the real run: if this fails, the
		// constants above no longer describe what the engine emits.
		f := stampedFromWire(t, jsSQLLineBefore)
		if f.RuleID != "" {
			t.Fatalf("the pre-change line must have no rule_id, got %q", f.RuleID)
		}
		if f.Fingerprint != recordedJSSQLFingerprint {
			t.Fatalf("fingerprint = %s, recorded %s", f.Fingerprint, recordedJSSQLFingerprint)
		}
		if f.FingerprintV1 != recordedJSSQLFingerprintV1 {
			t.Fatalf("fingerprint_v1 = %s, recorded %s", f.FingerprintV1, recordedJSSQLFingerprintV1)
		}
	})

	t.Run("the finding with its new rule_id keeps the recorded fingerprint", func(t *testing.T) {
		f := stampedFromWire(t, jsSQLLineAfter)
		if f.RuleID != "SEC-JS_SQL_TEMPLATE" {
			t.Fatalf("rule_id = %q, want SEC-JS_SQL_TEMPLATE", f.RuleID)
		}
		if f.Fingerprint != recordedJSSQLFingerprint {
			t.Errorf("fingerprint moved: got %s, recorded %s", f.Fingerprint, recordedJSSQLFingerprint)
		}
		if f.FingerprintV1 != recordedJSSQLFingerprintV1 {
			t.Errorf("fingerprint_v1 moved: got %s, recorded %s", f.FingerprintV1, recordedJSSQLFingerprintV1)
		}
		if got := models.FingerprintIdentityComponents(f); !slices.Contains(got, "rule=SEC-JS_SQL_TEMPLATE") {
			t.Errorf("identity components %q lack rule=SEC-JS_SQL_TEMPLATE", got)
		}
	})

	t.Run("all four checks: rule_id equal to the id does not move identity", func(t *testing.T) {
		for _, id := range []string{
			"SEC-JS_EVAL",
			"SEC-JS_INNER_HTML",
			"SEC-JS_DOCUMENT_WRITE",
			"SEC-JS_SQL_TEMPLATE",
		} {
			t.Run(id, func(t *testing.T) {
				legacy := models.Finding{
					ID:       id,
					Title:    "JS pattern",
					Severity: models.SeverityHigh,
					Source:   models.SourceWhitebox,
					Category: "injection",
					Endpoint: "src/app.ts:12",
					Evidence: "el.innerHTML = userInput;",
				}
				withRule := legacy
				withRule.RuleID = id

				models.StampIdentity(&legacy)
				models.StampIdentity(&withRule)

				if legacy.Fingerprint != withRule.Fingerprint {
					t.Errorf("fingerprint moved: %s -> %s", legacy.Fingerprint, withRule.Fingerprint)
				}
				if legacy.FingerprintV1 != withRule.FingerprintV1 {
					t.Errorf("fingerprint_v1 moved: %s -> %s", legacy.FingerprintV1, withRule.FingerprintV1)
				}
				if !slices.Contains(models.FingerprintIdentityComponents(withRule), "rule="+id) {
					t.Errorf("identity components lack rule=%s", id)
				}
			})
		}
	})

	t.Run("control: any other rule_id string would move it", func(t *testing.T) {
		// Why the rule_id is the id verbatim and not a namespaced
		// "javascript.pattern/..." like python.ast/... — that spelling
		// re-identifies the finding.
		f := stampedFromWire(t, jsSQLLineAfter)
		f.RuleID = "javascript.pattern/JS_SQL_TEMPLATE"
		models.StampIdentity(&f)
		if f.Fingerprint == recordedJSSQLFingerprint {
			t.Fatal("a different rule_id left the fingerprint unchanged; the control no longer proves anything")
		}
	})
}
