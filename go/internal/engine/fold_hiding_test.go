package engine

// CL3 / F-B1 (VERIFY-SEC rc.4): a fold must never lower a member below the status
// that member earns alone, and two values that are different constructs must not
// fold at all.
//
// CL2-2 made the folded finding take its PROVIDER member's own judgement, and the
// provider finding may be a published sample. A real generic secret on the same
// line (`password = "<real>"; tok = "<sample token>"`), beside it in a JSON object,
// or in the same literal (`password = "<real><sample token>"`) lost its status to
// the sample, and the real value had no finding of its own: an adversary gets that
// for free by appending a published token to the line.
//
// Both directions are pinned. A real value is never hidden by a sample, and a
// sample is never raised by a real neighbour: a sample alone, and two samples
// together, are still WARN.

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// fhSamples are published or sequential sample tokens (VERIFY-SEC's SAMPLE set).
var fhSamples = []struct{ name, token string }{
	{"slack", "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"},
	{"github", "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"},
	{"npm", "npm_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"stripe", "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"},
}

func fhReal(seed int64) string { return pfRandom(seed, 14) + "Qz!7" }

// fhShapes put a real generic value and a sample token in one file.
var fhShapes = []struct {
	name  string
	build func(real, sample string) string
	// sameLiteral: one string literal holds both, so one finding may cover both.
	sameLiteral bool
	// realUndetected: no engine version reads the real value at all (the closing
	// quote of a JSON member's key breaks HARDCODED_PASSWORD's pattern, and
	// Semgrep's rule matches an assignment, not a member), so the only finding is
	// the sample token's. v3.7.0 BLOCKed that line because it never judged a sample.
	// The fold cannot hide what was never found, so the sample token keeps v3.7.0's
	// status on a line that holds a credential no rule can read (neighbor.go).
	realUndetected bool
}{
	{"real-then-sample-on-one-line", func(r, s string) string { return fmt.Sprintf(`password = "%s"; tok = "%s"`, r, s) }, false, false},
	{"sample-then-real-on-one-line", func(r, s string) string { return fmt.Sprintf(`tok = "%s"; password = "%s"`, s, r) }, false, false},
	{"json-siblings", func(r, s string) string { return fmt.Sprintf(`cfg = {"password": "%s", "tok": "%s"}`, r, s) }, false, true},
	{"real-around-sample-in-one-literal", func(r, s string) string { return fmt.Sprintf(`password = "%s%s%s"`, r[:10], s, r[4:14]) }, true, false},
	{"real-then-sample-in-one-literal", func(r, s string) string { return fmt.Sprintf(`password = "%s:%s"`, r, s) }, true, false},
	{"sample-then-real-in-one-literal", func(r, s string) string { return fmt.Sprintf(`password = "%s:%s"`, s, r) }, true, false},
}

// A real generic value keeps its status next to a sample token, in every shape and
// with or without Semgrep reading the line. It is v3.7.0's status (BLOCK) and the
// status the real value earns alone.
func TestCL3_RealValueIsNeverHiddenBySampleToken(t *testing.T) {
	for _, sample := range fhSamples {
		for _, sh := range fhShapes {
			for _, withSemgrep := range []bool{true, false} {
				for seed := int64(1); seed <= 3; seed++ {
					real := fhReal(seed)
					name := fmt.Sprintf("%s/%s/semgrep=%v/seed=%d", sample.name, sh.name, withSemgrep, seed)
					alone := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, real)+"\n", withSemgrep), "c.py")
					if alone != "BLOCK" {
						t.Fatalf("control: a real password alone is %s, want BLOCK", alone)
					}
					evs := pfScan(t, "c.py", sh.build(real, sample.token)+"\n", withSemgrep)
					findings, _ := finalizeOnce(t, evs, scanOpts{})
					best := "none"
					realFinding := false
					for _, f := range findings {
						if f.Category != "secrets" {
							continue
						}
						if statusRank(f.Status) > statusRank(best) {
							best = f.Status
						}
						if f.Status == "BLOCK" && strings.HasPrefix(f.RuleID, "secrets/") && f.RuleID != "secrets/SLACK_TOKEN" &&
							f.RuleID != "secrets/GITHUB_TOKEN" && f.RuleID != "secrets/NPM_TOKEN" && f.RuleID != "secrets/STRIPE_LIVE_KEY" {
							realFinding = true
						}
					}
					if best != "BLOCK" {
						t.Errorf("%s: %s, a real password beside a sample token was lowered (v3.7.0: BLOCK)", name, best)
						continue
					}
					if !sh.sameLiteral && !sh.realUndetected && !realFinding {
						t.Errorf("%s: the real password has no finding of its own; two values that are different constructs were folded", name)
					}
				}
			}
		}
	}
}

// The other direction: a sample is never raised. A sample token alone, a sample
// generic value beside a sample token, and two sample tokens are WARN, and a real
// neighbour on ANOTHER line changes nothing about them.
func TestCL3_SamplesAreNeverRaised(t *testing.T) {
	for _, sample := range fhSamples {
		other := fhSamples[(len(sample.name)+1)%len(fhSamples)]
		cases := map[string]string{
			"sample alone":              fmt.Sprintf(`tok = "%s"`, sample.token),
			"sample generic and token":  fmt.Sprintf(`password = "changeme:1234567890"; tok = "%s"`, sample.token),
			"two samples, two literals": fmt.Sprintf(`a = "%s"; b = "%s"`, sample.token, other.token),
			"two samples, one literal":  fmt.Sprintf(`password = "%s:%s"`, sample.token, other.token),
			"sample with seq junk":      fmt.Sprintf(`password = "%s:1234567890"`, sample.token),
		}
		for name, line := range cases {
			for _, withSemgrep := range []bool{true, false} {
				got := pfStatusAt(t, pfScan(t, "c.py", line+"\n", withSemgrep), "c.py")
				if got != "WARN" {
					t.Errorf("%s/%s semgrep=%v: %s, want WARN (a sample is not raised)", sample.name, name, withSemgrep, got)
				}
			}
		}
		// The real value on its own line does not raise the sample on the next.
		evs := append(pfScan(t, "r.py", fmt.Sprintf(`password = "%s"`, fhReal(9))+"\n", true), pfScan(t, "s.py", fmt.Sprintf(`tok = "%s"`, sample.token)+"\n", true)...)
		if got := pfStatusAt(t, evs, "s.py"); got != "WARN" {
			t.Errorf("%s: a sample in one file is %s next to a real password in another", sample.name, got)
		}
		if got := pfStatusAt(t, evs, "r.py"); got != "BLOCK" {
			t.Errorf("%s: the real password in another file is %s", sample.name, got)
		}
	}
}

// Findings from the native secrets scanner that name different assignment targets
// are different constructs: the collapse keeps them apart. The same target is one
// construct, and a Semgrep finding on a single-target line still folds into it
// (the `be` password twins).
func TestCL3_CollapseKeepsDifferentCredentialTargetsApart(t *testing.T) {
	mk := func(rule, ident string) models.Finding {
		return models.Finding{
			ID: "SEC-X", RuleID: rule, Title: rule, Category: "secrets", Endpoint: "c.py:1", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Evidence: "x", Fix: "f", Secret: &models.SecretRef{Identifier: ident, File: "c.py"},
		}
	}
	semgrep := models.Finding{
		ID: "python-hardcoded-secret-assignment", RuleID: "python-hardcoded-secret-assignment", Title: "Hardcoded secret in an assignment",
		Category: "secrets", Endpoint: "c.py:1", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		SourceTier: models.TierSemgrepShim, Evidence: "y", Fix: "g",
	}
	rules := func(fs []models.Finding) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.RuleID)
		}
		return strings.Join(out, ",")
	}
	t.Run("different targets stay two findings", func(t *testing.T) {
		out := CollapseDuplicateLocations([]models.Finding{mk("secrets/HARDCODED_PASSWORD", "password"), mk("secrets/SLACK_TOKEN", "tok"), semgrep})
		if !strings.Contains(rules(out), "secrets/HARDCODED_PASSWORD") || !strings.Contains(rules(out), "secrets/SLACK_TOKEN") {
			t.Errorf("a password and a token bound to different names were folded: %s", rules(out))
		}
	})
	t.Run("the same target is one construct and Semgrep folds into it", func(t *testing.T) {
		out := CollapseDuplicateLocations([]models.Finding{mk("secrets/HARDCODED_PASSWORD", "password"), mk("secrets/SLACK_TOKEN", "password"), semgrep})
		if len(out) != 1 {
			t.Errorf("one literal read by two rules and Semgrep must be one finding, got %s", rules(out))
		}
	})
	t.Run("a Semgrep finding folds into a single target", func(t *testing.T) {
		out := CollapseDuplicateLocations([]models.Finding{mk("secrets/HARDCODED_PASSWORD", "password"), semgrep})
		if len(out) != 1 {
			t.Errorf("the native password finding and its Semgrep twin must fold, got %s", rules(out))
		}
	})
	t.Run("the result does not depend on the order", func(t *testing.T) {
		in := []models.Finding{mk("secrets/HARDCODED_PASSWORD", "password"), mk("secrets/SLACK_TOKEN", "tok"), semgrep}
		var want string
		for _, p := range permutations(len(in)) {
			ord := make([]models.Finding, len(in))
			for i, j := range p {
				ord[i] = in[j]
			}
			sorted := rules(CollapseDuplicateLocations(ord))
			parts := strings.Split(sorted, ",")
			sortStrings(parts)
			got := strings.Join(parts, ",")
			if want == "" {
				want = got
			}
			if got != want {
				t.Errorf("order %v folds to %s, another to %s", p, got, want)
			}
		}
	})
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var _ = evidence.Evidence{}

// F-C1: a real JWT with junk glued to its signature keeps v3.7.0's status.
func TestCL3_RealJWTWithJunkKeepsItsStatus(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		jwt := "eyJ" + pfRandom(seed*10+1, 30) + ".eyJ" + pfRandom(seed*10+2, 40) + "." + pfRandom(seed*10+3, 43)
		for _, stmt := range []string{`password = "%s"`, `JWT = "%s"`, `api_key = "%s"`} {
			control := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(stmt, jwt)+"\n", true), "c.py")
			if control != "BLOCK" {
				t.Fatalf("control: a real JWT in %q is %s, want BLOCK", stmt, control)
			}
			for _, tail := range []string{"-0123456789", "_0123456789", ":1234567890", "abcdefghijklmnopqrstuvwxyz", "0123456789abcdef", "123456789012"} {
				for _, withSemgrep := range []bool{true, false} {
					if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(stmt, jwt+tail)+"\n", withSemgrep), "c.py"); got != "BLOCK" {
						t.Errorf("%q + %q semgrep=%v: %s, want BLOCK (v3.7.0)", stmt, tail, withSemgrep, got)
					}
				}
			}
		}
	}
}

// F-C2: a Slack token with short ids and one segment too many.
func TestCL3_CutSlackTokenWithShortIdsKeepsItsStatus(t *testing.T) {
	for _, v := range []string{
		"xoxb-" + "799204-080813-8" + "gRdc2-0123456789",
		"xoxb-7992041-0808132-" + pfRandom(5, 12) + "-0123456789",
		"xoxb-79920412-08081322-" + pfRandom(6, 16) + "-0123456789",
	} {
		for _, withSemgrep := range []bool{true, false} {
			if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, v)+"\n", withSemgrep), "c.py"); got != "BLOCK" {
				t.Errorf("%s semgrep=%v: %s, want BLOCK (v3.7.0)", v, withSemgrep, got)
			}
		}
	}
}

// RC-9e (i) and (ii) on a mixed fixture of real values, sample tokens and both
// together, with Semgrep reading every line: each file's strongest status is the
// same alone and in the set, in any input order. No sample is raised by a real
// neighbour (i) and no real value is hidden by a sample (ii).
func TestCL3_MixedFixtureKeepsIsolation(t *testing.T) {
	slack, gh := fhSamples[0].token, fhSamples[1].token
	files := []struct{ file, content, want string }{
		{"a_real.py", fmt.Sprintf(`password = "%s"`, fhReal(41)), "BLOCK"},
		{"b_sample.py", fmt.Sprintf(`tok = "%s"`, slack), "WARN"},
		{"c_real_and_sample_lines.py", fmt.Sprintf(`password = "%s"; tok = "%s"`, fhReal(42), slack), "BLOCK"},
		{"d_real_around_sample.py", fmt.Sprintf(`password = "%s%s%s"`, fhReal(43)[:10], gh, fhReal(44)[4:14]), "BLOCK"},
		{"e_two_samples.py", fmt.Sprintf(`password = "%s:%s"`, slack, gh), "WARN"},
		{"f_sample_with_junk.py", fmt.Sprintf(`password = "%s:1234567890"`, slack), "WARN"},
		{"g_real_token_with_junk.py", fmt.Sprintf(`password = "%s:1234567890"`, pfProviders[0].token), "BLOCK"},
		{"tests/test_h.py", fmt.Sprintf(`password = "%s"; tok = "%s"`, fhReal(45), slack), ""},
		{"docs/i.md", fmt.Sprintf(`password = "%s"; tok = "%s"`, fhReal(46), slack), ""},
	}
	var all []evidence.Evidence
	alone := map[string]string{}
	for _, f := range files {
		evs := pfScan(t, f.file, f.content+"\n", true)
		alone[f.file] = pfStatusAt(t, evs, f.file)
		if f.want != "" && alone[f.file] != f.want {
			t.Errorf("%s alone is %s, want %s", f.file, alone[f.file], f.want)
		}
		all = append(all, evs...)
	}
	for seed := int64(0); seed < 6; seed++ {
		in := append([]evidence.Evidence(nil), all...)
		rand.New(rand.NewSource(seed)).Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
		for _, f := range files {
			got := pfStatusAt(t, in, f.file)
			if statusRank(got) > statusRank(alone[f.file]) {
				t.Errorf("order %d: %s is %s in the set but %s alone: raised by another occurrence (invariant i)", seed, f.file, got, alone[f.file])
			}
			if statusRank(got) < statusRank(alone[f.file]) {
				t.Errorf("order %d: %s is %s in the set but %s alone: hidden by another occurrence (invariant ii)", seed, f.file, got, alone[f.file])
			}
		}
	}
}
