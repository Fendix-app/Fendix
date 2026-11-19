package secrets

import (
	"fmt"
	"math/rand"
	"testing"
)

// The value classifier of RC-10b: a sample is recognised by its VALUE, and a real
// credential never trips it.

func TestExtendedSyntheticRecognisesSamples(t *testing.T) {
	samples := map[string]string{
		"alternating run (the plan-doc shape)": "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0j1K2l3M4n5O6p7Q8r",
		"sequential letters":                   "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		// old: "token_9876543210zyxwvu" (a run inside a longer value). new (OR-89): the whole value is a run.
		"descending digits":                     "9876543210zyxwvu",
		"a run of x":                            "ghp_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"stripe documentation body":             "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc",
		"jwt.io sample signature":               "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxM" + "jM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwp" + "MeJf36POk6yJV_adQssw5c",
		"aws documented access key id":          "AKIA" + "IOSFODNN7EXAMPLE",
		"aws documented secret":                 "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"slack sequential digits":               "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
		"periodic class pattern":                "a1B2a1B2a1B2a1B2" + "a1B2a1B2a1B2a1B2",
		"low diversity":                         "abababababababababab",
		"template marker: your-":                "your-api-token-goes-here",
		"template marker: angle brackets":       "<paste-token>",
		"template marker: interpolation":        "${SECRET_TOKEN}",
		"template marker: masked":               "sk_live_********************",
		"a common sample password":              "password123",
		"a common sample password, mixed case":  "Password123",
		"a common sample password, with spaces": "  changeit ",
		"leetspeak sample":                      "P@ssw0rd",
		"administrator":                         "administrator",
	}
	for name, v := range samples {
		if !extendedSynthetic(v) {
			t.Errorf("%s: %q is not recognised as synthetic", name, v)
		}
	}
}

func TestExtendedSyntheticLeavesRealFormatValuesAlone(t *testing.T) {
	real := map[string]string{
		"github, checksum valid":   "ghp_" + "939WtxKhJoVW1aucqQ" + "iORTI3zKRmGx4RaDXs",
		"github, random":           "ghp_" + "bUid1uhY2HKVrWfQkw" + "LoZufvsnPPElS4YRQB",
		"aws id":                   "AKIA" + "XNBYXL2PFSVNFHDL",
		"aws secret":               "cGRXMHvXJBZgM8OQso9u" + "9EPGO+ZSwQgsydGc8Oop",
		"stripe":                   "sk_live_" + "819QiMBRbjhU" + "gnaunrIqoXhi",
		"slack":                    "xoxb-" + "755729417849-880746575526" + "5-C4iLF51u3NoEvbIITuELkgqf",
		"google":                   "AIzaHcUNmwYizom5maG" + "PcUdUQbcz9NOuujbzVBB",
		"database password":        "kRUv6bJ9uSn2yWrKwAjm",
		"npm":                      "npm_ykbJyQrihjc4Q5iz" + "4DYAWDoa9g6gsL1z7uhL",
		"a password with symbols":  "UYOo0f52uLnk#9!",
		"jwt signed with a secret": "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMGE3NTcyY2MiLCJpc3MiOi" + "JodHRwczovL2F1dGguYWNtZS1jb3JwLm5ldCJ9.PuaGRItAwV6M0dYY1S0Az" + "T5M8Ck2R7F9g7VgF8aulVM",
		"a long password that merely contains a common word": "Xpassword-9f3k2Qw8",
		"password1234 is not on the list":                    "password1234",
	}
	for name, v := range real {
		if extendedSynthetic(v) {
			t.Errorf("%s: %q was flagged synthetic", name, v)
		}
	}
}

// A real credential is drawn from a high-entropy alphabet. Thousands of
// provider-shaped random values, from a fixed seed, never trip a signal.
func TestExtendedSyntheticNeverFiresOnRandomProviderShapedValues(t *testing.T) {
	rng := rand.New(rand.NewSource(20261116))
	alphabets := []struct{ name, chars string }{
		{"base62", "0123456789ABCDEFGHIJKLMNOPQRSTU" + "VWXYZabcdefghijklmnopqrstuvwxyz"},
		{"hex", "0123456789abcdef"},
		{"urlsafe", "0123456789ABCDEFGHIJKLMNOPQRSTUV" + "WXYZabcdefghijklmnopqrstuvwxyz-_"},
		{"upper+digits", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	}
	shapes := []struct {
		prefix string
		n      int
	}{{"ghp_", 36}, {"sk_live_", 24}, {"AKIA", 16}, {"npm_", 36}, {"AIza", 35}, {"", 40}, {"", 32}, {"xoxb-", 24}}
	flagged := 0
	for i := 0; i < 6000; i++ {
		a := alphabets[rng.Intn(len(alphabets))]
		sh := shapes[rng.Intn(len(shapes))]
		b := make([]byte, sh.n)
		for j := range b {
			b[j] = a.chars[rng.Intn(len(a.chars))]
		}
		v := sh.prefix + string(b)
		if extendedSynthetic(v) {
			flagged++
			if flagged <= 5 {
				t.Errorf("a random %s value %q was flagged synthetic", a.name, v)
			}
		}
	}
	if flagged > 0 {
		t.Errorf("%d of 6000 random provider-shaped values were flagged synthetic", flagged)
	}
}

func TestCommonPlaceholderIsExactNotSubstring(t *testing.T) {
	for _, v := range []string{"password", "PASSWORD", "Passw0rd", "changeit", "ChangeMe", "p@ssw0rd", "12345678", "qwerty", "letmein", "hunter2", "administrator"} {
		if !isCommonPlaceholderValue(v) {
			t.Errorf("%q should be on the common-placeholder list", v)
		}
	}
	for _, v := range []string{"password!", "mypassword9", "Xpassword", "passwordpassword", "root1", "UYOo0f52uLnk#9!", ""} {
		if isCommonPlaceholderValue(v) {
			t.Errorf("%q must not match: the list is exact, never a substring", v)
		}
	}
}

// The classifier carries the value signals and the name signal apart: a name
// records intent, not the value, so it never makes a value "synthetic".
func TestValueBasedExcludesTheNameSignal(t *testing.T) {
	s := classifyPlaceholder(`FAKE_API_KEY = "jACk8FkYZFnP7A`+`b5DSDVe0Qq7wBe"`, len(`FAKE_API_KEY = "`), "jACk8FkYZFnP7A"+"b5DSDVe0Qq7wBe")
	if !s.NamePrefix || !s.isPlaceholder() {
		t.Fatalf("control: the FAKE_ name must still make a placeholder: %+v", s)
	}
	if s.valueBased() {
		t.Errorf("a FAKE_ name alone must not count as value evidence: %+v", s)
	}
	for _, v := range []string{"password123", "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0j1K2l3M4n5O6p7Q8r", "hunter2"} {
		sig := classifyPlaceholder(fmt.Sprintf(`api_key = "%s"`, v), len(`api_key = "`), v)
		if !sig.valueBased() || !sig.isPlaceholder() {
			t.Errorf("%q: %+v", v, sig)
		}
	}
}
