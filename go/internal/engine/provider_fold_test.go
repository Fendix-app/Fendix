package engine

// CL2-2 / R3-SEC-B1 (independent verification, owner ruling OR-88).
//
// A provider rule's token and a generic rule's assignment value can be the SAME
// string literal, and a Semgrep rule reads it a third time. The three are one
// construct (RC-9), so the collapse keeps one of them and folds the others in.
// When the generic finding was the one kept, the RC-10b synthetic judgement of
// ITS value ("<slack token>:1234567890": a sequential digit run) demoted the
// whole folded finding, and the provider's own, real, random token was reported
// as a WARN with exit 0 where v3.7.0 and rc.1 BLOCKed. GitHub, Stripe, OpenAI
// and AWS id keys were spared only because their CRITICAL severity makes them
// the representative; Slack, npm and Google (HIGH) were not.
//
// The rule these tests pin: a provider rule's token is judged on its OWN value.
// A synthetic judgement made about a different, generic finding's value never
// lowers a folded finding below what the provider finding earns on its own
// evidence, and a provider token that is itself synthetic keeps the rc.3
// treatment (WARN in source, INFO in documentation).
//
// All of it runs through the real secrets scanner and the real orchestrator
// finalization (finalizeOnce). The dev image has no Semgrep, so the Semgrep
// finding the hosted scan adds on the same line is built by hand with the fields
// the Semgrep scanner gives it.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// pfRandom is a random alphanumeric string of n bytes from a seeded source, so a
// test value never carries a synthetic signal by accident and never changes.
func pfRandom(seed int64, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" + "fghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// pfProviders are real-format, random provider tokens, one per provider rule the
// RC-10b fixtures cover, with the severity the rule gives them.
var pfProviders = []struct {
	name, token string
	critical    bool
}{
	{"slack", "xoxb-" + "755729417849-8807465755265-" + pfRandom(1, 24), false},
	{"google", "AIza" + pfRandom(2, 35), false},
	{"npm", "npm_" + pfRandom(3, 36), false},
	{"github", "ghp_" + pfRandom(4, 36), true},
	{"stripe", "sk_live_" + pfRandom(5, 24), true},
	{"openai", "sk-" + pfRandom(6, 48), true},
	{"aws-id", "AKIA" + strings.ToUpper(pfRandom(7, 16)), true},
	{"anthropic", "sk-ant-" + pfRandom(8, 40), true},
}

// pfJunk is what is put around a token inside the same string literal. extended
// marks the junk the RC-10b classifier added (a sequential, descending or periodic
// run, a template marker): v3.7.0 and rc.1 did not read those, so a real token
// with such junk BLOCKed there and must BLOCK now, however many rules read the
// literal. The others (a dominant character, a placeholder word) were already
// fixture signals in v3.7.0, which read them off the generic finding's value.
var pfJunk = []struct {
	name, pre, post string
	extended        bool
}{
	{"digits-ascending-colon", "", ":1234567890", true},
	{"digits-ascending-dash", "", "-0123456789", true},
	{"digits-ascending-direct", "", "0123456789", true},
	{"digits-descending", "", ".9876543210", true},
	{"letters-ascending-colon", "", ":abcdefghij", true},
	{"letters-ascending-direct", "", "abcdefghij", true},
	{"periodic", "", ":a1Ba1Ba1Ba1B" + "a1Ba1Ba1Ba1B", true},
	{"template-marker", "", "${SECRET}", true},
	{"digits-prefix", "1234567890:", "", true},
	{"arn-with-sequential-account", "arn:xoxb:secretsmanager:us-east-1:123456789012:secret:", "", true},
	{"both-sides", "0123456789-", ":1234567890", true},
	{"published-example-suffix", "", ":4eC39HqLyjWD" + "arjtT1zdp7dc", true},
	{"dominant-char", "", "-aaaaaaaaaa", false},
	{"placeholder-word-suffix", "", "-changeme", false},
	{"example-word-suffix", "", ":example", false},
	{"changeme-prefix", "changeme-", "", false},
	{"dummy-prefix", "dummy-", "", false},
	{"password-prefix", "password-", "", false},
}

// pfStatements wrap a value in the generic rules' assignment shapes.
var pfStatements = []struct{ name, file, format string }{
	{"password", "settings.py", `password = "%s"`},
	{"secret-config", "settings.py", `app.secret_key = "%s"`},
	{"api-key", "settings.py", `api_key = "%s"`},
	{"env", "prod.env", `DB_PASSWORD=%s`},
	{"db-url", "settings.py", `DATABASE_URL = "postgres://admin:%s@db.internal:5432/app"`},
}

// pfScan scans one file with the real secrets scanner, adds the Semgrep finding
// the hosted scan reports on each secrets line when withSemgrep, and returns the
// evidence.
func pfScan(t *testing.T, rel, content string, withSemgrep bool) []evidence.Evidence {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	evs, err := secrets.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if withSemgrep {
		seen := map[string]bool{}
		for _, e := range evs {
			if e.Category != "secrets" || seen[e.Endpoint] {
				continue
			}
			seen[e.Endpoint] = true
			evs = append(evs, pfSemgrepTwin(e.Endpoint))
		}
	}
	return evs
}

// pfSemgrepTwin is the Semgrep finding on one assignment line: a lower-trust
// tier, a different rule, the same construct.
func pfSemgrepTwin(endpoint string) evidence.Evidence {
	line := endpoint
	return evidence.Evidence{
		ID: "python-hardcoded-secret-assignment", RuleID: "python-hardcoded-secret-assignment",
		Title: "Hardcoded secret found in assignment", Category: "secrets", Endpoint: endpoint, Line: &line,
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim,
		Confidence: models.ConfidenceMedium, References: []string{"CWE-798"},
		Evidence: "password = \"[REDACTED]\"", Fix: "Move the credential to a secrets manager and rotate it.",
	}
}

// pfStatusAt is the strongest status the finalization gives a secrets finding at
// the given file (any line), or "none".
func pfStatusAt(t *testing.T, evs []evidence.Evidence, file string) string {
	t.Helper()
	findings, _ := finalizeOnce(t, evs, scanOpts{})
	best := "none"
	for _, f := range findings {
		if f.Category != "secrets" {
			continue
		}
		eps := append([]string{f.Endpoint}, f.AffectedEndpoints...)
		hit := false
		for _, ep := range eps {
			if strings.HasPrefix(ep, file+":") {
				hit = true
			}
		}
		if hit && statusRank(f.Status) > statusRank(best) {
			best = f.Status
		}
	}
	return best
}

// pfProviderEvidence is the evidence a provider rule produced, if any: the rule
// can decline a literal its boundary check rejects (a Google key followed by "-").
func pfProviderEvidence(evs []evidence.Evidence) (evidence.Evidence, bool) {
	for _, e := range evs {
		if e.ProviderAnchored && strings.HasPrefix(e.RuleID, "secrets/") && e.Category == "secrets" &&
			e.RuleID != "secrets/PRIVATE_KEY" {
			return e, true
		}
	}
	return evidence.Evidence{}, false
}

// A provider token's status does not depend on what is put around it inside the
// same literal, nor on which generic rule reads the literal, nor on Semgrep
// reading it too. The control is the same statement with the bare token; for a
// real random token it is BLOCK in source.
//
//   - Junk v3.7.0 never read (extended): BLOCK in every pairing.
//   - Junk v3.7.0 already read off the generic value (a dominant character, a
//     placeholder word): BLOCK whenever the provider rule fired and its own
//     value is clean. The generic finding's judgement of its own value is not the
//     provider token's.
func TestCL2_ProviderTokenKeepsItsStatusWhenFoldedWithAGeneric(t *testing.T) {
	for _, st := range pfStatements {
		for _, p := range pfProviders {
			control := pfStatusAt(t, pfScan(t, st.file, fmt.Sprintf(st.format, p.token)+"\n", true), st.file)
			if control != "BLOCK" {
				t.Fatalf("control: a bare random %s token in %q is %s, want BLOCK", p.name, st.format, control)
			}
			for _, j := range pfJunk {
				for _, withSemgrep := range []bool{true, false} {
					name := fmt.Sprintf("%s/%s/%s/semgrep=%v", st.name, p.name, j.name, withSemgrep)
					evs := pfScan(t, st.file, fmt.Sprintf(st.format, j.pre+p.token+j.post)+"\n", withSemgrep)
					if len(evs) == 0 {
						// Nothing reads this literal at all (a token glued to a longer identifier
						// fails every rule's boundary): detection scope, unchanged since v3.7.0.
						continue
					}
					got := pfStatusAt(t, evs, st.file)
					required := j.extended
					if !required {
						if pe, ok := pfProviderEvidence(evs); ok && !pe.Placeholder {
							required = true
						}
					}
					if required && got != "BLOCK" {
						t.Errorf("%s: %s, but the bare token is BLOCK: a judgement of the generic value lowered a real provider token", name, got)
					}
					if !required && statusRank(got) < statusRank("WARN") {
						t.Errorf("%s: %s, a real provider token with junk must be at least WARN", name, got)
					}
				}
			}
		}
	}
}

// The same in documentation: a real-format provider token is a WARN there (not
// provable offline), whatever the generic rule's value looks like. It is not
// lowered to INFO by the generic value's synthetic signal.
func TestCL2_ProviderTokenInDocumentationIsNotLoweredByTheGenericValue(t *testing.T) {
	for _, p := range pfProviders {
		if p.critical && p.name == "github" {
			continue // a random ghp_ token is not checksum-valid; covered by the loop below too
		}
		control := pfStatusAt(t, pfScan(t, "README.md", fmt.Sprintf(`password = "%s"`, p.token)+"\n", true), "README.md")
		if control == "none" {
			t.Fatalf("control: %s in README.md not reported", p.name)
		}
		for _, j := range pfJunk {
			got := pfStatusAt(t, pfScan(t, "README.md", fmt.Sprintf(`password = "%s"`, j.pre+p.token+j.post)+"\n", true), "README.md")
			if j.extended && statusRank(got) < statusRank(control) {
				t.Errorf("%s + %s in README.md is %s, but the bare token is %s", p.name, j.name, got, control)
			}
		}
	}
}

// A provider token that is itself synthetic (a documented example, a sequential
// or dominant-character body) keeps the rc.3 treatment however it is wrapped:
// WARN in source, INFO in documentation. The judgement is the token's own.
func TestCL2_SyntheticProviderTokenKeepsItsRc3Treatment(t *testing.T) {
	synthetic := []struct{ name, token string }{
		{"slack-sequential", vSlackSeq},
		{"google-dominant", vGoogleX},
		{"npm-dominant", vNPMXs},
		{"github-sequential", vGHSequential},
		{"github-alternating", vGHAlternate},
		{"stripe-published-example", vStripeDoc},
		{"aws-documented-example", vAWSExampleID},
	}
	for _, p := range synthetic {
		for _, withSemgrep := range []bool{true, false} {
			alone := pfStatusAt(t, pfScan(t, "settings.py", fmt.Sprintf(`MY_TOKEN = "%s"`, p.token)+"\n", withSemgrep), "settings.py")
			if alone != "WARN" {
				t.Fatalf("control: synthetic %s alone in source is %s, want WARN", p.name, alone)
			}
			for _, wrap := range []string{`password = "%s"`, `password = "%s:1234567890"`, `api_key = "%s-0123456789"`} {
				if got := pfStatusAt(t, pfScan(t, "settings.py", fmt.Sprintf(wrap, p.token)+"\n", withSemgrep), "settings.py"); got != "WARN" {
					t.Errorf("synthetic %s as %q (semgrep=%v) in source is %s, want WARN", p.name, wrap, withSemgrep, got)
				}
				if got := pfStatusAt(t, pfScan(t, "README.md", fmt.Sprintf(wrap, p.token)+"\n", withSemgrep), "README.md"); got != "INFO" {
					t.Errorf("synthetic %s as %q (semgrep=%v) in documentation is %s, want INFO", p.name, wrap, withSemgrep, got)
				}
			}
		}
	}
}

// A provable credential in documentation keeps BLOCK when a generic rule's
// synthetic value is folded with it.
func TestCL2_ProvableProviderTokenInDocumentationKeepsBlock(t *testing.T) {
	for _, j := range pfJunk {
		if strings.HasSuffix(j.name, "-direct") {
			continue // alnum glued to the token: the GitHub rule's boundary declines it, so nothing is provable
		}
		got := pfStatusAt(t, pfScan(t, "docs/setup.md", fmt.Sprintf(`password = "%s"`, j.pre+vGHProvable+j.post)+"\n", true), "docs/setup.md")
		if got != "BLOCK" {
			t.Errorf("a checksum-valid GitHub token + %s in documentation is %s, want BLOCK", j.name, got)
		}
	}
}

// The twins of a plain password still fold: the native generic finding and the
// Semgrep finding on one line are one finding, and a sample password stays
// demoted. Only a PROVIDER member of the fold can lift a generic finding.
func TestCL2_PasswordTwinsStillFoldAndSamplesStayDemoted(t *testing.T) {
	real := pfScan(t, "settings.py", `password = "`+pfRandom(11, 18)+`#9!"`+"\n", true)
	findings, _ := finalizeOnce(t, real, scanOpts{})
	n := 0
	for _, f := range findings {
		if f.Category == "secrets" {
			n++
			if f.Status != "BLOCK" {
				t.Errorf("a real-looking password is %s, want BLOCK", f.Status)
			}
		}
	}
	if n != 1 {
		t.Errorf("the native password finding and its Semgrep twin are %d findings, want 1", n)
	}
	for _, sample := range []string{"password123", "hunter2", "changeme:1234567890", "sample-password-1234567890"} {
		if got := pfStatusAt(t, pfScan(t, "settings.py", fmt.Sprintf(`password = "%s"`, sample)+"\n", true), "settings.py"); got != "WARN" {
			t.Errorf("sample password %q is %s, want WARN (fixture-shaped in source)", sample, got)
		}
	}
}

// RC-9e on a mixed fixture: occurrences with different evidence are never one
// finding, so one is never raised by another (i) and never hidden by another (ii),
// in any input order.
func TestCL2_MixedFixtureKeepsIsolation(t *testing.T) {
	type occ struct{ file, content string }
	slackA := "xoxb-" + "755729417849-8807465755265-" + pfRandom(21, 24)
	slackB := "xoxb-" + "755729417849-8807465755265-" + pfRandom(22, 24)
	occs := []occ{
		{"svc/a.py", fmt.Sprintf(`password = "%s:1234567890"`, slackA) + "\n"},                                      // real token + digit run
		{"svc/b.py", fmt.Sprintf(`password = "%s-0123456789"`, slackB) + "\n"},                                      // real token + digit run
		{"svc/c.py", `password = "changeme:1234567890"` + "\n"},                                                     // a sample
		{"svc/d.py", `password = "` + pfRandom(23, 18) + `#9!"` + "\n"},                                             // a real-looking password
		{"svc/e.py", fmt.Sprintf(`password = "%s"`, vSlackSeq) + "\n"},                                              // a synthetic provider token
		{"tests/test_f.py", fmt.Sprintf(`password = "%s:1234567890"`, slackA) + "\n"},                               // the same token in a test file
		{"docs/g.md", fmt.Sprintf(`password = "%s:1234567890"`, slackB) + "\n"},                                     // and in documentation
		{"svc/h.py", fmt.Sprintf(`password = "%s"`, "xoxb-"+"755729417849-8807465755265-"+pfRandom(24, 24)) + "\n"}, // bare
	}
	var all []evidence.Evidence
	alone := map[string]string{}
	for _, o := range occs {
		evs := pfScan(t, o.file, o.content, true)
		alone[o.file] = pfStatusAt(t, evs, o.file)
		all = append(all, evs...)
	}
	// Every occurrence must also have its expected status on its own. The
	// occurrences that carry a real token with junk are expected at what the
	// bare token earns at the same path.
	bare := func(file string, seed int64) string {
		tok := "xoxb-" + "755729417849-8807465755265-" + pfRandom(seed, 24)
		return pfStatusAt(t, pfScan(t, file, fmt.Sprintf(`password = "%s"`, tok)+"\n", true), file)
	}
	want := map[string]string{
		"svc/a.py": bare("svc/a.py", 31), "svc/b.py": bare("svc/b.py", 32), "svc/c.py": "WARN", "svc/d.py": "BLOCK", "svc/e.py": "WARN",
		"tests/test_f.py": bare("tests/test_f.py", 33), "docs/g.md": bare("docs/g.md", 34), "svc/h.py": "BLOCK",
	}
	if want["svc/a.py"] != "BLOCK" || want["svc/b.py"] != "BLOCK" || want["svc/h.py"] != "BLOCK" {
		t.Fatalf("control: a bare real Slack token must BLOCK in source, got %v", want)
	}
	for f, w := range want {
		if alone[f] != w {
			t.Errorf("%s alone is %s, want %s", f, alone[f], w)
		}
	}
	files := make([]string, 0, len(want))
	for f := range want {
		files = append(files, f)
	}
	sort.Strings(files)
	for seed := int64(0); seed < 6; seed++ {
		in := append([]evidence.Evidence(nil), all...)
		rand.New(rand.NewSource(seed)).Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
		for _, f := range files {
			got := pfStatusAt(t, in, f)
			if statusRank(got) > statusRank(alone[f]) {
				t.Errorf("order %d: %s is %s in the set but %s alone: raised by another occurrence (invariant i)", seed, f, got, alone[f])
			}
			if statusRank(got) < statusRank(alone[f]) {
				t.Errorf("order %d: %s is %s in the set but %s alone: hidden by another occurrence (invariant ii)", seed, f, got, alone[f])
			}
		}
	}
}

// TestCL2_MatrixDump prints the whole generic-rule x provider-rule x synthetic-class
// matrix as TABLE rows (run it with -v): statement, provider, junk, Semgrep present,
// the status the finalization gives, the status of the bare token, whether the
// provider rule fired and whether its own value was fixture-shaped. It asserts
// nothing; TestCL2_ProviderTokenKeepsItsStatusWhenFoldedWithAGeneric is the check.
func TestCL2_MatrixDump(t *testing.T) {
	for _, st := range pfStatements {
		for _, p := range pfProviders {
			control := pfStatusAt(t, pfScan(t, st.file, fmt.Sprintf(st.format, p.token)+"\n", true), st.file)
			for _, j := range pfJunk {
				for _, withSemgrep := range []bool{true, false} {
					evs := pfScan(t, st.file, fmt.Sprintf(st.format, j.pre+p.token+j.post)+"\n", withSemgrep)
					got := "none"
					if len(evs) > 0 {
						got = pfStatusAt(t, evs, st.file)
					}
					fired, own := "no", "-"
					if pe, ok := pfProviderEvidence(evs); ok {
						fired, own = "yes", map[bool]string{true: "fixture", false: "clean"}[pe.Placeholder]
					}
					t.Logf("TABLE\t%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\t%v", st.name, p.name, j.name, withSemgrep, got, control, fired, own, j.extended)
				}
			}
		}
	}
}
