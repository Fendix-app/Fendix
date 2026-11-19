package engine

// CL5 / OR-89: the whole-value rule for sample credentials.
//
// A credential value is a sample (a published example, a sequence, a repeated
// character, a template, a placeholder word, a common sample password) only when the
// WHOLE literal value is that form, optionally with closed-list junk: a placeholder
// word from the scanner's list, a template marker, or a separator run between two such
// parts. Anything else in the literal, a real value glued to a sample token, a
// remainder of any length, makes the value not a sample, and it keeps v3.7.0's status.
//
// Three more hidings (VERIFY-ACC rc.6 item 4) needed the remainder heuristics to give
// up: R6-B1 (real characters absorbed into a sample's natural tail), R6-B2 (a joiner
// trimmed from a base64-padded remainder), R6-B3 (a real token glued to a
// variable-length sample). All three are BLOCK in v3.7.0.

import (
	"fmt"
	"testing"
)

func wvStatus(t *testing.T, rel, line string, semgrep bool) string {
	t.Helper()
	return pfStatusAt(t, pfScan(t, rel, line+"\n", semgrep), rel)
}

// R6-B1 to R6-B3, as VERIFY-ACC reproduced them.
func TestCL5_R6Hidings(t *testing.T) {
	const slackSample = "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	const stripeSample = "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"
	const ghSample = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	realGH := "ghp_" + pfRandom(61, 36)
	realSlack := "xoxb-" + "631596320528-384265450152-" + pfRandom(62, 24)
	for name, line := range map[string]string{
		"R6-B1 real characters glued to the Stripe documentation key": `password = "sk_live_` + `4eC39HqLyjWDarjt` + `T1zdp7dcbK9mQ2vL"`,
		"R6-B1 on a bare name":                                  `TOKEN = "sk_live_` + `4eC39HqLyjWDarjt` + `T1zdp7dcbK9mQ2vL"`,
		"R6-B2 base64 padding after a colon":                    fmt.Sprintf(`password = "%s:Zk4Hq9=="`, stripeSample),
		"R6-B2 slash before":                                    fmt.Sprintf(`password = "%s/Km9#qLz"`, slackSample),
		"R6-B2 semicolon":                                       fmt.Sprintf(`password = "%s;Zk4Hq9x"`, ghSample),
		"R6-B2 pipe after":                                      fmt.Sprintf(`password = "%s|Zk4Hq9x"`, ghSample),
		"R6-B2 padded value before":                             fmt.Sprintf(`password = "Zk4Hq9==:%s"`, stripeSample),
		"R6-B3 a real GitHub token glued to a Slack sample":     fmt.Sprintf(`TOKEN = "%s%s"`, slackSample, realGH),
		"R6-B3 a real Slack token glued to the Stripe sample":   fmt.Sprintf(`password = "%s%s"`, stripeSample, realSlack),
		"R6-B3 a real GitHub token glued before a Slack sample": fmt.Sprintf(`password = "%s%s"`, realGH, slackSample),
	} {
		for _, withSemgrep := range []bool{true, false} {
			if got := wvStatus(t, "c.py", line, withSemgrep); got != "BLOCK" {
				t.Errorf("%s (semgrep=%v): %s, want BLOCK (v3.7.0: BLOCK)", name, withSemgrep, got)
			}
		}
	}
}

// Any text beside a sample token, of any length and any content that is not closed-list
// junk, makes the value not a sample: BLOCK, as in v3.7.0. The sweep covers every
// length from 1 to 12 of real-looking, symbol-heavy, digit-only and mixed text, joined
// by a colon, glued, before and after.
func TestCL5_AnyTextBesideASampleKeepsBlock(t *testing.T) {
	shapes := map[string]string{"real-looking": "Zk4Hq9xP2mLw", "symbol-heavy": "!@#$%^&*()_+", "digits": "483917256041", "mixed": "Zq7!Tk4@Wm9#"}
	for _, s := range f5Samples {
		for shape, content := range shapes {
			for n := 1; n <= 12; n++ {
				rem := content[:n]
				for _, v := range []string{s.token + ":" + rem, rem + ":" + s.token, s.token + rem, rem + s.token} {
					for _, withSemgrep := range []bool{true, false} {
						if got := wvStatus(t, "c.py", fmt.Sprintf(`password = "%s"`, v), withSemgrep); got != "BLOCK" {
							t.Errorf("%s/%s len %d %q semgrep=%v: %s, want BLOCK", s.name, shape, n, v, withSemgrep, got)
						}
					}
				}
			}
		}
	}
}

// A sample with closed-list junk is still a sample: WARN.
func TestCL5_SampleWithClosedListJunkIsWarn(t *testing.T) {
	for _, s := range f5Samples {
		for _, v := range []string{
			s.token + ":changeme", s.token + "-example", s.token + ":${X}", s.token + "<your-token>", s.token + "-0123456789",
			s.token + ":0123456789", "your-" + s.token, "changeme-" + s.token, "dummy_" + s.token, "example/" + s.token,
			s.token + ":" + f5Samples[(len(s.name)+1)%len(f5Samples)].token,
			s.token + ":your-key-here", s.token + ":{{ token }}", s.token + ":REPLACE_ME", s.token + ":----------",
			s.token + ":...........", s.token + ":~~~~~~~~~~", s.token + ":xxxxxxxxxx", s.token + ":0000000000",
			s.token + ":abcdefghij", s.token + "_EXAMPLE", s.token + ":dummy", s.token + ":redacted",
		} {
			for _, withSemgrep := range []bool{true, false} {
				if got := wvStatus(t, "c.py", fmt.Sprintf(`password = "%s"`, v), withSemgrep); got != "WARN" {
					t.Errorf("%s: %q semgrep=%v: %s, want WARN", s.name, v, withSemgrep, got)
				}
			}
		}
		// The exact sample alone is WARN in code and INFO in documentation.
		if got := wvStatus(t, "c.py", fmt.Sprintf(`password = "%s"`, s.token), true); got != "WARN" {
			t.Errorf("%s alone in code: %s, want WARN", s.name, got)
		}
		if got := wvStatus(t, "README.md", fmt.Sprintf(`password = "%s"`, s.token), true); got != "INFO" {
			t.Errorf("%s alone in documentation: %s, want INFO", s.name, got)
		}
	}
}

// Two of VERIFY-SEC's 18 "genuine junk" remainders are not closed-list junk: `test` (deliberately
// absent from the placeholder list, it hides inside `latest` and `attest`) and `(documentation)`.
// Beside a sample they keep v3.7.0's status, BLOCK: the cost of the whole-value rule.
func TestCL5_TwoRemaindersThatAreNotClosedListJunkKeepBlock(t *testing.T) {
	for _, s := range f5Samples {
		for _, junk := range []string{":test", ":(documentation)"} {
			if got := wvStatus(t, "c.py", fmt.Sprintf(`password = "%s"`, s.token+junk), true); got != "BLOCK" {
				t.Errorf("%s: %q is %s, want BLOCK (v3.7.0)", s.name, s.token+junk, got)
			}
		}
	}
}
