package semgrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Two identity defects in the semgrep family, neither visible on a machine
// without semgrep installed — which is every machine the local suite runs on,
// so the whole family was untested until a scan through the released image
// exercised it.
//
//  1. The rule id carried the TEMP DIRECTORY the rules were written to:
//     "tmp.fendix-semgrep-rules-1072928901.flask-route-no-auth-decorator".
//     That number is fresh per run, so once rule id became an identity input
//     every semgrep finding got a new identity on every scan — the RC-5 defect
//     back again, worse, because it churns without the file even changing.
//
//  2. Nothing distinguished two matches of one rule in one file. Five
//     unprotected Flask routes collapsed into ONE identity, so suppressing the
//     finding for one route silently suppressed the other four.

func TestRuleIDDropsTheTemporaryRulesDirectory(t *testing.T) {
	for _, raw := range []string{
		"tmp.fendix-semgrep-rules-1072928901.flask-route-no-auth-decorator",
		"tmp.fendix-semgrep-rules-2173727481.flask-route-no-auth-decorator",
		"var.folders.pm.fendix-semgrep-rules-99.flask-route-no-auth-decorator",
	} {
		if got := normalizeCheckID(raw); got != "flask-route-no-auth-decorator" {
			t.Errorf("normalizeCheckID(%q) = %q", raw, got)
		}
	}
}

// Two runs of one scan must agree, which is the whole point.
func TestRuleIDIsStableAcrossRuns(t *testing.T) {
	a := normalizeCheckID("tmp.fendix-semgrep-rules-1072928901.python.lang.security.audit.eval")
	b := normalizeCheckID("tmp.fendix-semgrep-rules-2173727481.python.lang.security.audit.eval")
	if a != b {
		t.Errorf("the same rule got two ids across runs: %q vs %q", a, b)
	}
	if a != "python.lang.security.audit.eval" {
		t.Errorf("dotted rule ids must survive intact, got %q", a)
	}
}

// A registry rule that never went through our temp directory is untouched.
func TestRuleIDLeavesAForeignNamespaceAlone(t *testing.T) {
	const id = "python.flask.security.injection.tainted-sql-string"
	if got := normalizeCheckID(id); got != id {
		t.Errorf("normalizeCheckID(%q) = %q — a rule we did not write must not be rewritten", id, got)
	}
}

// --- distinguishing two matches of one rule ------------------------------

func flaskResult(fn string, line int) semgrepResult {
	return semgrepResult{
		CheckID: "tmp.fendix-semgrep-rules-123.flask-route-no-auth-decorator",
		Path:    "app/views.py",
		Start:   semgrepLineCol{Line: line},
		Extra: semgrepExtra{
			Message:  "Flask route '" + fn + "' has no auth-style decorator",
			Severity: "WARNING",
			Lines:    "requires login",
			Metavars: map[string]semgrepMetavar{
				"$APP":  {AbstractContent: "app"},
				"$FUNC": {AbstractContent: fn},
			},
		},
	}
}

func TestTwoRoutesUnderOneRuleAreTwoFindings(t *testing.T) {
	seen := map[string]string{}
	for _, fn := range []string{"fetch_image", "proxy_any", "read_report", "download", "go_away"} {
		ev, ok := mapResult(ptr(flaskResult(fn, 8)), "")
		if !ok {
			t.Fatalf("%s produced no finding", fn)
		}
		fp := models.Fingerprint(ev.ToFinding())
		if prior, clash := seen[fp]; clash {
			t.Errorf("routes %q and %q share one identity — suppressing either hides both", fn, prior)
		}
		seen[fp] = fn
	}
}

// The same route, moved down the file, is the same finding.
func TestARouteThatMovedKeepsItsIdentity(t *testing.T) {
	at8, _ := mapResult(ptr(flaskResult("fetch_image", 8)), "")
	at52, _ := mapResult(ptr(flaskResult("fetch_image", 52)), "")
	if models.Fingerprint(at8.ToFinding()) != models.Fingerprint(at52.ToFinding()) {
		t.Error("moving the route down the file changed its identity")
	}
}

// A metavariable can bind to whatever the rule matched — including a
// credential, for a rule that matches hardcoded secrets. Identity must never
// consume that, so only plain identifiers are eligible.
func TestOnlyIdentifierMetavariablesReachIdentity(t *testing.T) {
	const credential = "sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs"
	r := semgrepResult{
		CheckID: "tmp.fendix-semgrep-rules-123.hardcoded-secret",
		Path:    "config.py",
		Start:   semgrepLineCol{Line: 3},
		Extra: semgrepExtra{
			Message:  "hardcoded credential",
			Severity: "ERROR",
			Metavars: map[string]semgrepMetavar{
				"$KEY":   {AbstractContent: "STRIPE_SECRET_KEY"},
				"$VALUE": {AbstractContent: `"` + credential + `"`},
			},
		},
	}
	ev, ok := mapResult(&r, "")
	if !ok {
		t.Fatal("no finding")
	}
	if strings.Contains(ev.Symbol, credential) || strings.Contains(ev.Sink, credential) {
		t.Errorf("credential material reached an identity field: symbol=%q sink=%q", ev.Symbol, ev.Sink)
	}
	if !strings.Contains(ev.Symbol+ev.Sink, "STRIPE_SECRET_KEY") {
		t.Errorf("the safe identifier was dropped too: symbol=%q sink=%q", ev.Symbol, ev.Sink)
	}
}

func ptr(r semgrepResult) *semgrepResult { return &r }

// --- semgrep redacts what we were relying on -----------------------------

// Semgrep OSS without a logged-in account replaces `extra.lines` (and
// `extra.fingerprint`) with the literal string "requires login". Two
// consequences, both real:
//
//   - every semgrep finding showed "requires login" as its EVIDENCE, which is
//     what a user reads to decide whether the finding is real;
//   - and it left nothing to distinguish two matches of one rule in one file,
//     so five unprotected Flask routes shared one identity.
//
// The matched line is on disk at a path and line number semgrep does give us,
// so we read it ourselves rather than depending on what semgrep chose to send.

func TestRedactedLinesAreRecoveredFromDisk(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app/views.py", "import os\n@app.route('/fetch')\ndef fetch_image():\n    pass\n")

	r := semgrepResult{
		CheckID: "tmp.fendix-semgrep-rules-1.flask-route-no-auth-decorator",
		Path:    root + "/app/views.py",
		Start:   semgrepLineCol{Line: 3},
		Extra:   semgrepExtra{Message: "Flask route has no auth decorator", Severity: "WARNING", Lines: semgrepRedactedLines},
	}
	ev, ok := mapResult(&r, root)
	if !ok {
		t.Fatal("no finding")
	}
	if ev.Evidence == semgrepRedactedLines {
		t.Error("evidence is still semgrep's placeholder — a user reads this to triage")
	}
	if !strings.Contains(ev.Evidence, "def fetch_image") {
		t.Errorf("evidence is not the matched line: %q", ev.Evidence)
	}
}

// Real evidence that semgrep DID send is trusted as-is.
func TestSemgrepSuppliedLinesAreKept(t *testing.T) {
	r := semgrepResult{
		CheckID: "x.rule", Path: "app/views.py", Start: semgrepLineCol{Line: 3},
		Extra: semgrepExtra{Message: "m", Severity: "WARNING", Lines: "cursor.execute(q)"},
	}
	ev, _ := mapResult(&r, "")
	if ev.Evidence != "cursor.execute(q)" {
		t.Errorf("evidence = %q, want the line semgrep sent", ev.Evidence)
	}
}

func TestTwoRoutesInOneFileAreTwoFindingsFromDisk(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app/views.py", ""+
		"@app.route('/a')\n"+
		"def fetch_image():\n"+
		"    pass\n"+
		"@app.route('/b')\n"+
		"def proxy_any():\n"+
		"    pass\n")

	fps := map[string]int{}
	for _, line := range []int{2, 5} {
		r := semgrepResult{
			CheckID: "tmp.fendix-semgrep-rules-1.flask-route-no-auth-decorator",
			Path:    root + "/app/views.py",
			Start:   semgrepLineCol{Line: line},
			Extra:   semgrepExtra{Message: "no auth decorator", Severity: "WARNING", Lines: semgrepRedactedLines},
		}
		ev, _ := mapResult(&r, root)
		fps[models.Fingerprint(ev.ToFinding())] = line
	}
	if len(fps) != 2 {
		t.Errorf("two routes in one file produced %d identity/identities", len(fps))
	}
}

// A rule that matches a hardcoded credential reads a line containing it. The
// identity must not.
// Masking has to be TARGETED. Blanket-masking every literal removed the only
// thing telling five Flask routes apart — the route path is a literal, and for
// a route-shaped rule the path IS the identity, exactly as the endpoint is for
// a blackbox finding. So the mask has to hit credentials and miss route paths.
func TestMaskingKeepsStructuralLiteralsAndDropsCredentialShapedOnes(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		masked     bool
	}{
		{"a route path", `@app.route("/proxy")`, false},
		{"a long route path", `@app.route("/api/v1/organizations/members")`, false},
		{"a config key", `config.get("database_url")`, false},
		{"a stripe key", `KEY = "sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs"`, true},
		{"a slack token", `TOKEN = "xoxb-9999999999-aAaAaAaAaAaAaAaAaAaA"`, true},
		{"a base64 blob", `SECRET = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCB2YWx1ZQ=="`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := maskStringLiterals(tc.line)
			if tc.masked && got == tc.line {
				t.Errorf("credential-shaped literal survived into identity: %q", got)
			}
			if !tc.masked && got != tc.line {
				t.Errorf("structural literal was masked away, losing the discriminator: %q -> %q", tc.line, got)
			}
		})
	}
}

// The five-route case, stated as the outcome that matters.
func TestFiveRoutesUnderOneRuleAreFiveFindings(t *testing.T) {
	root := t.TempDir()
	body := ""
	lines := map[string]int{}
	for i, route := range []string{"/fetch", "/proxy", "/report", "/download", "/go"} {
		body += "@app.route(\"" + route + "\")\ndef handler" + string(rune('a'+i)) + "():\n    pass\n"
		lines[route] = i*3 + 1
	}
	writeFile(t, root, "app/views.py", body)

	fps := map[string]string{}
	for route, line := range lines {
		r := semgrepResult{
			CheckID: "tmp.fendix-semgrep-rules-1.flask-route-no-auth-decorator",
			Path:    root + "/app/views.py",
			Start:   semgrepLineCol{Line: line},
			Extra:   semgrepExtra{Message: "no auth decorator", Severity: "WARNING", Lines: semgrepRedactedLines},
		}
		ev, _ := mapResult(&r, root)
		fp := models.Fingerprint(ev.ToFinding())
		if prior, clash := fps[fp]; clash {
			t.Errorf("routes %q and %q share one identity", route, prior)
		}
		fps[fp] = route
	}
	if len(fps) != 5 {
		t.Errorf("five routes produced %d identities", len(fps))
	}
}

func TestARecoveredLineNeverCarriesACredentialIntoIdentity(t *testing.T) {
	const credential = "sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs"
	root := t.TempDir()
	writeFile(t, root, "config.py", "STRIPE_SECRET_KEY = \""+credential+"\"\n")

	r := semgrepResult{
		CheckID: "tmp.fendix-semgrep-rules-1.hardcoded-secret",
		Path:    root + "/config.py",
		Start:   semgrepLineCol{Line: 1},
		Extra:   semgrepExtra{Message: "hardcoded credential", Severity: "ERROR", Lines: semgrepRedactedLines},
	}
	ev, _ := mapResult(&r, root)

	if strings.Contains(ev.Sink, credential) {
		t.Errorf("the credential reached the identity input: %q", ev.Sink)
	}
	if !strings.Contains(ev.Sink, "STRIPE_SECRET_KEY") {
		t.Errorf("the safe discriminator was lost with it: %q", ev.Sink)
	}
	// Two different credentials under different names stay distinct.
	writeFile(t, root, "other.py", "SLACK_TOKEN = \"xoxb-9999999999-aaaaaaaaaaaaaaaaaaaa\"\n")
	r2 := r
	r2.Path = root + "/other.py"
	ev2, _ := mapResult(&r2, root)
	if ev.Sink == ev2.Sink {
		t.Errorf("two different credentials collapsed to one operation: %q", ev.Sink)
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
