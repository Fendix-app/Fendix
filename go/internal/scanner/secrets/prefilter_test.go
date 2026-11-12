package secrets

import (
	"math/rand"
	"strings"
	"testing"
)

// Every pattern has a prefilter, except the ones that cannot be certain of a
// literal, and the sets are the ones expected for the patterns whose cost
// matters. A pattern that silently lost its filter would make every scan slower;
// one that gained a wrong filter would lose findings.
func TestPatternsHaveLiteralPrefilters(t *testing.T) {
	want := map[string][]string{
		"AWS_ACCESS_KEY":    {"akia"},
		"PRIVATE_KEY":       {"private key-----"},
		"JWT_TOKEN":         {"eyj"},
		"STRIPE_LIVE_KEY":   {"sk_live_"},
		"ANTHROPIC_API_KEY": {"sk-ant-"},
	}
	all := append(append([]pattern{}, patterns...), envPatterns...)
	none := 0
	for _, p := range all {
		if w, ok := want[p.id]; ok {
			if strings.Join(p.required, "|") != strings.Join(w, "|") {
				t.Errorf("%s: required = %q, want %q", p.id, p.required, w)
			}
		}
		if len(p.required) == 0 {
			none++
			t.Logf("%s has no prefilter", p.id)
		}
	}
	if none > 2 {
		t.Errorf("%d of %d patterns have no literal prefilter; the scan would run their regex on every line", none, len(all))
	}
}

// The prefilter never rejects a line its pattern matches. The lines are built
// from the literals each pattern needs, with their case, neighbours and
// separators varied at random, so a pattern is tried on lines that are near
// misses as well as on matches, plus non-ASCII lines and long lines.
func TestPrefilterNeverDropsAMatchingLine(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	frags := []string{
		"AKIA", "akia", "AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key", "AWS-SECRET", "Aws Secret Key",
		"-----BEGIN RSA PRIVATE KEY-----", "-----begin private key-----", "api_key", "API-KEY", "apikey", "ApiToken",
		"access_token", "secret_key", "client_secret", "auth_token", "password", "PASSWD", "pwd", "Password",
		"app.config['SECRET_KEY_HMAC']", "jwt_secret", "hmac_key", "encryption_key", "eyJhbGciOiJIUzI1NiJ9", "eyJ",
		"postgres://u:p@h/db", "MONGODB://a:b@c", "jdbc:mysql://h/db?user=u&password=pw", "redis://", "://",
		"ghp_", "gho_", "ghs_", "sk_live_", "xoxb-", "AIza", "sk-ant-", "sk-proj-", "sk-", "service_account",
		`"type": "service_account"`, "SECRET", "KEY", "TOKEN", "=", ":", " = ", `"`, `'`, "x", "Z", "0", "9", "_", "-",
		strings.Repeat("a", 40), strings.Repeat("A1", 20), "é", "ſecret", "paſsword", "K", "日本語", " ", "\t",
	}
	all := append(append([]pattern{}, patterns...), envPatterns...)
	for n := 0; n < 200000; n++ {
		var b strings.Builder
		for k := rng.Intn(8) + 1; k > 0; k-- {
			b.WriteString(frags[rng.Intn(len(frags))])
		}
		line := b.String()
		lower, ascii := strings.ToLower(line), isASCII(line)
		for i := range all {
			if all[i].mayMatch(lower, ascii) {
				continue
			}
			if all[i].regex.MatchString(line) {
				t.Fatalf("%s: the prefilter %q dropped a line its pattern matches: %q", all[i].id, all[i].required, line)
			}
		}
	}
}
