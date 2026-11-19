package secrets

// CL3 / F-B1: a sample token does not vouch for a line that also holds a
// credential no rule can read (a JSON member whose quoted key breaks the password
// patterns).

import (
	"fmt"
	"testing"
)

func nbSlackEvidence(t *testing.T, line string) (placeholder, synthetic, found bool) {
	t.Helper()
	for _, e := range scanOne(t, "c.py", line+"\n") {
		if e.RuleID == "secrets/SLACK_TOKEN" {
			return e.Placeholder, e.SyntheticValue, true
		}
	}
	return false, false, false
}

func TestSampleTokenBesideAnUnreadableCredentialKeepsV370Status(t *testing.T) {
	const sample = "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	real := ptRandom(51, 14) + "Qz!7"
	for name, line := range map[string]string{
		"json member before":   fmt.Sprintf(`cfg = {"password": "%s", "tok": "%s"}`, real, sample),
		"json member after":    fmt.Sprintf(`cfg = {"tok": "%s", "password": "%s"}`, sample, real),
		"single quotes":        fmt.Sprintf(`cfg = {'tok': '%s', 'api_token': '%s'}`, sample, real),
		"minified":             fmt.Sprintf(`{"password":"%s","tok":"%s"}`, real, sample),
		"client secret member": fmt.Sprintf(`{"client_secret": "%s", "tok": "%s"}`, ptRandom(52, 30), sample),
	} {
		ph, syn, found := nbSlackEvidence(t, line)
		if !found {
			t.Fatalf("%s: the Slack rule did not read the sample token", name)
		}
		if ph || syn {
			t.Errorf("%s: the sample token is still a sample (placeholder=%v synthetic=%v) on a line with an unreadable credential", name, ph, syn)
		}
	}
}

// The other direction: nothing on the line that could be a real credential, so the
// sample stays a sample.
func TestSampleTokenStaysASampleWithoutARealLookingNeighbor(t *testing.T) {
	const sample = "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	for name, line := range map[string]string{
		"alone":                    fmt.Sprintf(`tok = "%s"`, sample),
		"placeholder password":     fmt.Sprintf(`{"password": "changeme", "tok": "%s"}`, sample),
		"common password":          fmt.Sprintf(`{"password": "password123", "tok": "%s"}`, sample),
		"label with spaces":        fmt.Sprintf(`{"password": "Enter your password", "tok": "%s"}`, sample),
		"a url under a token key":  fmt.Sprintf(`{"token": "https://example.test/oauth/token", "tok": "%s"}`, sample),
		"a key that only mentions": fmt.Sprintf(`{"token_url": "%s", "tok": "%s"}`, ptRandom(53, 20), sample),
		"a secret reference":       fmt.Sprintf(`{"secret": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", "tok": "%s"}`, sample),
		"a template":               fmt.Sprintf(`{"api_key": "${API_KEY_VALUE}", "tok": "%s"}`, sample),
		"another sample":           fmt.Sprintf(`{"token": "ghp_`+`0123456789abcdefghijklmnopqrstuvwxyz", "tok": "%s"}`, sample),
		"a real token has its own": fmt.Sprintf(`{"token": "ghp_%s", "tok": "%s"}`, ptRandom(54, 36), sample),
		"a short value":            fmt.Sprintf(`{"password": "Abc12", "tok": "%s"}`, sample),
		"not a credential key":     fmt.Sprintf(`{"username": "%s", "tok": "%s"}`, ptRandom(55, 16), sample),
	} {
		ph, syn, found := nbSlackEvidence(t, line)
		if !found {
			t.Fatalf("%s: the Slack rule did not read the sample token", name)
		}
		if !ph || !syn {
			t.Errorf("%s: the sample token is no longer a sample (placeholder=%v synthetic=%v)", name, ph, syn)
		}
	}
	// A sample judged so by a signal v3.7.0 already read is not restored: it was a sample then.
	ph, _, found := nbSlackEvidence(t, fmt.Sprintf(`{"password": "%s", "tok": "xoxb-`+`0000000000-0000000000-0000000000000000"}`, ptRandom(56, 18)))
	if !found || !ph {
		t.Error("a repeated-character token was restored to real by a neighbour; v3.7.0 already read it as a sample")
	}
}

// OR-89 (a): a neighbouring member's value is junk only when the WHOLE value is a sample
// form or closed-list junk, judged the way a credential value is judged (the whole-value
// rule). A placeholder word, a sequence or a sample token with real text beside it is
// not junk: the member could be a real credential, and the sample token on the line
// keeps v3.7.0's status. (rc.6 read the member's remainder past a placeholder word or a
// sequence as junk when it was short or sequence-like; see the g9 rows `changeme123`,
// `dummyvalue123`, `fakepassword1`.)
func TestNeighborMemberIsJunkOnlyWhenTheWholeValueIsASampleForm(t *testing.T) {
	const sample = "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	for name, tc := range map[string]struct {
		member   string
		wantSamp bool // the sample token stays a sample (the member is junk)
	}{
		"placeholder word":               {"changeme", true},
		"template":                       {"<password>", true},
		"mustache":                       {"{{ password }}", true},
		"reference":                      {"${DB_PASSWORD}", true},
		"your-password-here":             {"your_password_here", true},
		"sequence":                       {"abcdefghijklmnop", true},
		"repeated":                       {"xxxxxxxxxxxxxxxx", true},
		"stars":                          {"********", true},
		"sample token with prefix":       {"sk_test_abcdefghijklmnop", true},
		"a word and a separator and one": {"changeme-your-password-here", true},
		// real text beside, glued, or after a word: not junk
		"placeholder word and digits":       {"changeme123", false},
		"placeholder word and real text":    {"changeme-Kq8vZx2m", false},
		"dummy word and digits":             {"dummyvalue123", false},
		"fake word and digit":               {"fakepassword1", false},
		"sequence then real text":           {"abcdefghijklmnopKq8vZx2", false},
		"real text then sequence":           {"Kq8vZx2mabcd" + "efghijklmnop", false},
		"sample token then real text":       {"sk_test_" + "abcdefghijklmno" + "pqrstuvwxZk4Hq9x", false},
		"a shell variable":                  {"$DB_PASSWORD", false},
		"a word nobody listed":              {"hunter2hunter2", false},
		"documentation word is not on list": {"REDACTED_VALUE_HERE", false},
	} {
		line := fmt.Sprintf(`{"password": "%s", "tok": "%s"}`, tc.member, sample)
		ph, syn, found := nbSlackEvidence(t, line)
		if !found {
			t.Fatalf("%s: the Slack rule did not read the sample token", name)
		}
		if got := ph && syn; got != tc.wantSamp {
			t.Errorf("%s: member %q: the sample token is a sample = %v, want %v", name, tc.member, got, tc.wantSamp)
		}
	}
}
