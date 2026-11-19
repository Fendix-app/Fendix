package secrets

// CL2-2 / R3-SEC-B1: a value that carries a provider token is judged on the token.

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func ptRandom(seed int64, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" + "fghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

var ptReal = map[string]string{
	"slack":     "xoxb-" + "755729417849-8807465755265-" + ptRandom(1, 24),
	"google":    "AIza" + ptRandom(2, 35),
	"npm":       "npm_" + ptRandom(3, 36),
	"github":    "ghp_" + ptRandom(4, 36),
	"stripe":    "sk_live_" + ptRandom(5, 24),
	"openai":    "sk-" + ptRandom(6, 48),
	"aws-id":    "AKIA" + strings.ToUpper(ptRandom(7, 16)),
	"anthropic": "sk-ant-" + ptRandom(8, 40),
}

func ptExtended(value string) bool { return classifyPlaceholder(value, 0, value).Extended }

// A real token with junk around it is not synthetic, whatever the junk is and
// whether or not the token's own rule would have matched it.
func TestExtendedSyntheticJudgesTheTokenNotTheTextAroundIt(t *testing.T) {
	junk := []struct{ pre, post string }{
		{"", ""}, {"", ":1234567890"}, {"", "-0123456789"}, {"", "0123456789"}, {"", ".9876543210"}, {"", ":abcdefghij"},
		{"", "abcdefghij"}, {"", ":a1Ba1Ba1Ba1B" + "a1Ba1Ba1Ba1B"}, {"", "${SECRET}"}, {"1234567890:", ""}, {"0123456789-", ":1234567890"},
		{"arn:xoxb:secretsmanager:us-east-1:123456789012:secret:", ""}, {"abcdefghij:", ""},
	}
	for name, tok := range ptReal {
		for _, j := range junk {
			v := j.pre + tok + j.post
			if ptExtended(v) {
				t.Errorf("%s with junk %q|%q is judged synthetic: the junk was read as the token's own value", name, j.pre, j.post)
			}
		}
	}
}

// A token that is itself a sample stays a sample, with or without junk.
func TestExtendedSyntheticStillSeesASyntheticToken(t *testing.T) {
	samples := map[string]string{
		"slack-sequential":  "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
		"github-sequential": "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"github-periodic":   "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0j1K2l3M4n5O6p7Q8r",
		"google-dominant":   "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		"npm-dominant":      "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"stripe-published":  "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc",
		"aws-published":     "AKIA" + "IOSFODNN7EXAMPLE",
		"stripe-sequential": "sk_live_" + "abcdefghijklmnopqrstuvwx",
		"openai-sequential": "sk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
	}
	for name, tok := range samples {
		for _, v := range []string{tok, tok + ":1234567890", "dummy-" + tok, tok + "-0123456789"} {
			if !ptExtended(v) {
				t.Errorf("%s as %q is no longer judged synthetic", name, v)
			}
		}
	}
	// One real token among samples keeps the value real.
	if ptExtended(samples["slack-sequential"] + " " + ptReal["github"]) {
		t.Error("a value carrying a real token and a sample is judged synthetic")
	}
}

// A value with no provider token is judged whole, exactly as before.
func TestExtendedSyntheticWithoutAProviderTokenIsUnchanged(t *testing.T) {
	for v, want := range map[string]bool{
		"1234567890abcdefghijklmnop": true,
		"abcdefghijklmnopqrstuvwxyz": true,
		"Tr0ub4dor&3-xylophone":      false,
		ptRandom(9, 24) + "#9!":      false,
		// old (rc.6): true, the value CONTAINS a digit run. new (OR-89): false, only a WHOLE sample form is
		// synthetic, and a random 24-character value is not one.
		ptRandom(9, 24) + ":1234567890abcdef": false,
	} {
		if got := ptExtended(v); got != want {
			t.Errorf("%q: Extended = %v, want %v", v, got, want)
		}
	}
}

// containsProviderToken reads a value for a provider-shaped token wherever it sits.
func TestContainsProviderToken(t *testing.T) {
	for name, tok := range ptReal {
		if !containsProviderToken("x:" + tok + ":y") {
			t.Errorf("%s: a token inside a longer value was not found", name)
		}
	}
	for _, v := range []string{"Tr0ub4dor&3-xylophone", "changeme", "arn:aws:secretsmanager:us-east-1:123456789012:secret:a"} {
		if containsProviderToken(v) {
			t.Errorf("%q holds no provider token", v)
		}
	}
}

func TestRuleOrderIsTheRegistryOrder(t *testing.T) {
	if RuleOrder("secrets/HARDCODED_PASSWORD") >= RuleOrder("secrets/SLACK_TOKEN") {
		t.Error("the generic password rule is registered before the Slack rule")
	}
	if RuleOrder("secrets/GENERIC_API_KEY") >= RuleOrder("secrets/HARDCODED_PASSWORD") {
		t.Error("GENERIC_API_KEY is registered before HARDCODED_PASSWORD")
	}
	if RuleOrder("secrets/ENV_SECRET") <= RuleOrder("secrets/NPM_TOKEN") {
		t.Error("the .env rule follows the shared rules")
	}
	for _, id := range []string{"", "python-hardcoded-secret-assignment", "secrets/NOPE", "HARDCODED_PASSWORD"} {
		if RuleOrder(id) != -1 {
			t.Errorf("RuleOrder(%q) = %d, want -1", id, RuleOrder(id))
		}
	}
}

// ── CL3 ─────────────────────────────────────────────────────────────────────

func ptJWT(seed int64) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" + "ghijklmnopqrstuvwxyz0123456789_-"
	r := rand.New(rand.NewSource(seed))
	seg := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = b64[r.Intn(len(b64))]
		}
		return string(b)
	}
	return "eyJ" + seg(30) + ".eyJ" + seg(40) + "." + seg(43)
}

const ptJWTIOSample = "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I" + "kpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwp" + "MeJf36POk6yJV_adQssw5c"

// F-C1: a JWT's signature has no fixed length, so junk glued to it joined the
// token and the whole-token test called a real JWT synthetic.
func TestExtendedSyntheticJWTIsJudgedOnItsSignatureNotItsTail(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		jwt := ptJWT(seed)
		for _, tail := range []string{"", "-0123456789", "_0123456789", ":1234567890", "abcdefghijklmnopqrstuvwxyz", "0123456789abcdef", "123456789012", "-aaaaaaaaaa"} {
			if ptExtended(jwt + tail) {
				t.Errorf("a real JWT with %q glued to its signature is judged synthetic", tail)
			}
		}
	}
	// The published jwt.io sample is still a sample, tail or not.
	for _, tail := range []string{"", ":1234567890", "-0123456789"} {
		if !ptExtended(ptJWTIOSample + tail) {
			t.Errorf("the jwt.io sample token with %q is no longer judged synthetic", tail)
		}
	}
	// A JWT whose signature is itself sequential is a sample.
	// old (rc.6): a JWT with a sequential signature was synthetic, the signature being the whole
	// "token identity". new (OR-89): only a WHOLE sample form is, and a JWT with a real-looking header
	// and payload is not one.
	sample := "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abcdefghijklmnopqrstu" + "vwxyz0123456789ABCDEFG"
	if ptExtended(sample) {
		t.Error("a JWT with a sequential signature but a real-looking payload is judged a sample")
	}
}

// F-C2: a Slack token has at most 3 (bot) or 4 (user) segments after its prefix,
// so a further segment is not part of it, however short the ids are.
func TestExtendedSyntheticSlackSegmentsBeyondTheFormatAreNotTheToken(t *testing.T) {
	for _, v := range []string{
		"xoxb-" + "799204-080813-8" + "gRdc2-0123456789",
		"xoxb-" + "799204-080813-8gRdc" + "2zQ9pLm4-0123456789",
		"xoxb-7992041-0808132-" + ptRandom(11, 12) + "-0123456789",
		"xoxb-" + "75572941784" + "-" + "880746575526" + "-" + ptRandom(12, 24) + "-0123456789-abcdef",
		"xoxp-" + "799204-080813-445566-" + ptRandom(13, 20) + "-0123456789",
	} {
		if ptExtended(v) {
			t.Errorf("%q is judged synthetic: a segment past the token's format was read as part of it", v)
		}
	}
	// A bot token whose own segments are samples still is one.
	if !ptExtended("xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx") {
		t.Error("the documented Slack sample is no longer judged synthetic")
	}
}

// The whole-value rule (OR-89): a value is a sample only when the WHOLE value is a sample
// form, optionally with closed-list junk. Any other text beside a sample token, of any
// length and content, makes the value not a sample.
func TestExtendedSyntheticIsAnchoredToTheWholeValue(t *testing.T) {
	sample := "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	stripe := "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"
	real12 := ptRandom(31, 12)
	for name, tc := range map[string]struct {
		v    string
		want bool
	}{
		// The whole value is a sample, with or without closed-list junk.
		"sample alone":                      {sample, true},
		"stripe documentation key":          {stripe, true},
		"sequence after a separator":        {sample + ":1234567890", true},
		"sequence after a dash":             {sample + "-0123456789", true},
		"template after":                    {sample + "<your-token>", true},
		"variable after":                    {sample + "${VAR}", true},
		"template with words nobody listed": {sample + "<MyCompanyVaultEntry>", true},
		"variable with words nobody listed": {sample + "${COMPANY_VAULT_ENTRY_NAME}", true},
		"your-key-here form":                {sample + ":your-key-here", true},
		"a {{ name }} template":             {sample + ":{{ token }}", true},
		"REPLACE_ME":                        {sample + ":REPLACE_ME", true},
		"eight or more dashes":              {sample + ":----------", true},
		"dots":                              {sample + ":...........", true},
		"tildes":                            {sample + ":~~~~~~~~~~", true},
		"a repeated x":                      {sample + ":xxxxxxxxxx", true},
		"zeros":                             {sample + ":0000000000", true},
		"letters in sequence":               {sample + ":abcdefghij", true},
		"_EXAMPLE":                          {sample + "_EXAMPLE", true},
		"placeholder word before":           {"changeme-" + sample, true},
		"placeholder word after":            {sample + "-example", true},
		"your- before":                      {"your-" + sample, true},
		"dummy before":                      {"dummy_" + sample, true},
		"two samples":                       {sample + ":" + "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz", true},
		"two samples, glued":                {sample + "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz", true},
		"a sample and the stripe sample":    {stripe + ":" + sample, true},
		// Anything else beside a sample token: not a sample (R6-B1 to R6-B3 and the earlier hidings).
		"R6-B1 real characters after the stripe sample": {stripe + "bK9mQ2vL", false},
		"R6-B2 base64 padding after a colon":            {stripe + ":Zk4Hq9==", false},
		"R6-B2 slash":                                   {sample + "/Km9#qLz", false},
		"R6-B2 semicolon":                               {"ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz;Zk4Hq9x", false},
		"R6-B2 pipe":                                    {"ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz|Zk4Hq9x", false},
		"R6-B3 a real token glued to a sample":          {sample + "ghp_" + "xEV5YkK4ffdiw8D5J0" + "4p3NydrtS5PH3xpU2p", false},
		"R6-B3 a real token glued before a sample":      {"ghp_" + "xEV5YkK4ffdiw8D5J0" + "4p3NydrtS5PH3xpU2p" + sample, false},
		"a symbol-heavy password":                       {sample + ":P@ssw0rd!", false},
		"an 8-character password glued":                 {sample + "Tr0ub4d!", false},
		"before the sample":                             {"P@ssw0rd!" + sample, false},
		"only symbols":                                  {sample + "!@#$%^&*()", false},
		"alternating separators":                        {sample + "_-_-_-_-_-_-", false},
		"a password cut in two by the token":            {"Zk4Hq9x" + sample + "Lm7Pw2z", false},
		"one character":                                 {sample + ":Z", false},
		"a trailing separator":                          {sample + ":", false},
		"a leading separator":                           {":" + sample, false},
		"only separators (fewer than eight of one)":     {"-----_-", false},
		"a word nobody listed":                          {"test:" + sample, false},
		"test is not on the placeholder list":           {sample + ":test", false},
		"parenthesised text":                            {sample + ":(documentation)", false},
		"fewer than eight of one character":             {sample + ":-------", false},
		"real prefix":                                   {real12 + sample, false},
		"real suffix":                                   {sample + real12, false},
		"real text between two samples":                 {sample + ":" + real12 + ":" + stripe, false},
		"a real token alone":                            {ptReal["github"], false},
		"a real token and a sample":                     {sample + " " + ptReal["github"], false},
		"a real token with a digit run":                 {ptReal["slack"] + ":1234567890", false},
		"a digit run inside a longer value":             {real12 + ":1234567890", false},
		"a sample token inside a sentence":              {"use " + sample + " as the token", false},
	} {
		if got := ptExtended(tc.v); got != tc.want {
			t.Errorf("%s: Extended = %v, want %v (%q)", name, got, tc.want, tc.v)
		}
	}
}

// No length of any text beside a sample token, before or after, joined or glued, makes the
// value a sample. (The old sweep asserted that fewer than eight characters did; that was
// the remainder floor, removed by OR-89. Old: junk below 8, real from 8. New: always real.)
func TestNoRemainderOfAnyLengthMakesASampleValue(t *testing.T) {
	samples := map[string]string{
		"slack":  "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx",
		"github": "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz",
		"npm":    "npm_abcdefghijklmnopqrstuvwxyz0123456789",
		"stripe": "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc",
	}
	shapes := map[string]string{"real-looking": "Zk4Hq9xP2mLw", "symbol-heavy": "!@#$%^&*()_+", "digits": "483917256041", "mixed": "Zq7!Tk4@Wm9#"}
	for sname, sample := range samples {
		for shape, content := range shapes {
			for n := 1; n <= 12; n++ {
				rem := content[:n]
				for _, joiner := range []string{"", ":", "-", " ", "/", ";", "|", "="} {
					for _, v := range []string{sample + joiner + rem, rem + joiner + sample} {
						if ptExtended(v) {
							t.Errorf("%s/%s len %d %q is judged a sample", sname, shape, n, v)
						}
					}
				}
			}
		}
	}
}

// Every published or sequential sample form is still a sample when it is the whole value.
func TestWholeSampleFormsStayCovered(t *testing.T) {
	for name, v := range map[string]string{
		"alternating run":        "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0j1K2l3M4n5O6p7Q8r",
		"two alternating runs":   "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0jK1l2M3n4O5p6Q7r8",
		"sequential letters":     "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"descending run":         "9876543210zyxwvu",
		"a run of x":             "ghp_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"google run":             "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		"npm sequence":           "npm_abcdefghijklmnopqrstuvwxyz0123456789",
		"openai sequence":        "sk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		"stripe documentation":   "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc",
		"aws documented id":      "AKIA" + "IOSFODNN7EXAMPLE",
		"aws documented secret":  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"jwt.io sample":          ptJWTIOSample,
		"periodic":               "a1B2a1B2a1B2a1B2" + "a1B2a1B2a1B2a1B2",
		"low diversity":          "abababababababababab",
		"masked":                 "sk_live_********************",
		"slack sequence":         "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
		"common sample password": "Password123",
		"leetspeak sample":       "P@ssw0rd",
	} {
		if !extendedSynthetic(v) {
			t.Errorf("%s: %q is no longer judged synthetic", name, v)
		}
	}
}

// F-C1 and F-C2 need no cut now: a real JWT with a tail, and a Slack token with short
// ids and one segment too many, are simply not whole sample forms.
func TestWholeValueRuleCoversTheJWTAndShortSlackCases(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		jwt := ptJWT(seed)
		for _, tail := range []string{"", "-0123456789", "_0123456789", ":1234567890", "abcdefghijklmnopqrstuvwxyz", "0123456789abcdef", "123456789012"} {
			if ptExtended(jwt + tail) {
				t.Errorf("a real JWT with %q after it is judged a sample", tail)
			}
		}
	}
	for _, v := range []string{"xoxb-" + "799204-080813-8" + "gRdc2-0123456789", "xoxb-7992041-0808132-" + ptRandom(11, 12) + "-0123456789"} {
		if ptExtended(v) {
			t.Errorf("%q is judged a sample", v)
		}
	}
	sample := "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abcdefghijklmnopqrstu" + "vwxyz0123456789ABCDEFG"
	if ptExtended(sample) {
		t.Error("a JWT whose header and payload are real-looking and whose signature is a sequence is judged a sample")
	}
}

// A sequence or repeated run is read greedily, but the character after it can begin a
// closed-list part of its own: `...uvwx` + `your-key-here` continues the alphabet with
// the `y` of `your`. The value is sample + closed-list junk, so it is a sample; a cut of
// the run is allowed only when everything after it reads as sample parts, so real text
// is never absorbed (the VERIFY-SEC rc.6 junk-form rows: `your-key-here` glued after the
// Slack sample read BLOCK on rc.7 before this).
func TestSampleRunCutBeforeAClosedListPart(t *testing.T) {
	sample := "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	for name, tc := range map[string]struct {
		v    string
		want bool
	}{
		"your-key-here glued after the alphabet":     {sample + "your-key-here", true},
		"your_token_here glued":                      {sample + "your_token_here", true},
		"a template glued":                           {sample + "<your-token>", true},
		"repeated y then your-key-here":              {"xoxb-" + "1234567890-1234567890-yyyyyyyyyour-key-here", true},
		"the alphabet continues into real text":      {sample + "yKq8vZx2", false},
		"the alphabet continues, then real after":    {sample + "your-key-here-Kq8vZx2", false},
		"the alphabet continues into a real token":   {sample + "yghp_" + "xEV5YkK4ffdiw8D5J0" + "4p3NydrtS5PH3xpU2p", false},
		"repeated y then real text":                  {"xoxb-" + "1234567890-12345678" + "90-yyyyyyyyyKq8vZx2", false},
		"a cut that leaves a run of seven only":      {"xoxb-" + "1234567890-1234567890-abcdefgyour-key-here", false},
		"a cut that leaves a run of exactly eight":   {"xoxb-" + "1234567890-1234567890-abcdefghyour-key-here", true},
		"your-key-here is a closed list part only":   {sample + "yourKq8vZx2here", false},
		"a different word that starts like the list": {sample + "yourself", false},
	} {
		if got := ptExtended(tc.v); got != tc.want {
			t.Errorf("%s: Extended = %v, want %v (%q)", name, got, tc.want, tc.v)
		}
	}
}

// The run cut keeps the parse linear: a long value that never reads as sample parts, and
// one made of thousands of runs, are read in time proportional to their length.
func TestSampleRunCutIsLinear(t *testing.T) {
	long := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 20000) + "!Kq8"
	manyRuns := strings.Repeat("abcdefghij:", 40000) + "Kq8vZx2"
	start := time.Now()
	for _, v := range []string{long, manyRuns, manyRuns + manyRuns} {
		if sampleParts(v) {
			t.Errorf("a %d-byte value with real text at its end is judged a sample", len(v))
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the sample parse took %v on three long values", d)
	}
}

// A provider token's regex stops at the first character its alphabet does not hold, so
// the match can be a sample while the string literal it sits in is not: `sk_live_` + the
// documentation key + `:Zk4Hq9==` (R6-B2). The scanner reads the whole literal, not the
// match, for every provider-anchored rule (the rule is anchored to the whole value, not
// to what the token pattern matched). These are scanner-level, so a change that judged
// the match alone would go unnoticed by the value-level tests above.
func TestProviderTokenIsJudgedOnTheWholeLiteralItSitsIn(t *testing.T) {
	for _, tc := range []struct{ rule, token string }{
		{"secrets/SLACK_TOKEN", "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"},
		{"secrets/GITHUB_TOKEN", "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"},
		{"secrets/STRIPE_LIVE_KEY", "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"},
		{"secrets/NPM_TOKEN", "npm_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"secrets/GOOGLE_API_KEY", "AIza" + "abcdefghijklmnopqrstuvwxyz0123456789"[:35]},
		{"secrets/OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"},
		{"secrets/AWS_ACCESS_KEY", "AKIA" + "ABCDEFGHIJKLMNOP"},
	} {
		sampleLine := `tok = "` + tc.token + `"`
		es := evidenceByRule(scanOne(t, "c.py", sampleLine+"\n"), tc.rule)
		if len(es) == 0 {
			t.Fatalf("%s: the rule did not read the sample token alone: %s", tc.rule, sampleLine)
		}
		if !es[0].Placeholder || !es[0].SyntheticValue {
			t.Errorf("%s: the sample token alone is not a sample (placeholder=%v synthetic=%v)", tc.rule, es[0].Placeholder, es[0].SyntheticValue)
		}
		for _, tail := range []string{":Zk4Hq9x", "/Km9#qLz", ";Zk4Hq9x", " Zk4Hq9x", "!Zk4Hq9x", ":Zk4Hq9=="} {
			lines := map[string]string{
				"quoted": `tok = "` + tc.token + tail + `"`,
				"before": `tok = "` + strings.TrimLeft(tail, ":/;! ") + ":" + tc.token + `"`,
			}
			// Outside quotes a space or a semicolon ends the value: the tail is not in the literal.
			if !strings.ContainsAny(tail, " ;") {
				lines["unquoted"] = `tok = ` + tc.token + tail
			}
			for name, line := range lines {
				es := evidenceByRule(scanOne(t, "c.py", line+"\n"), tc.rule)
				if len(es) == 0 {
					continue // a tail the token pattern absorbs, or a line the rule does not read
				}
				for _, e := range es {
					if e.Placeholder || e.SyntheticValue {
						t.Errorf("%s %s tail %q: a sample token with real text in its literal is judged a sample (placeholder=%v synthetic=%v): %s",
							tc.rule, name, tail, e.Placeholder, e.SyntheticValue, line)
					}
				}
			}
		}
	}
}

// A provider prefix is not content: a literal that is a bare prefix, or a prefix and
// separators, is not a sample form.
func TestABareProviderPrefixIsNotASample(t *testing.T) {
	for _, p := range tokenPrefixes {
		for _, v := range []string{p, p + ":", p + "::", "-" + p} {
			if extendedSynthetic(v) {
				t.Errorf("%q is judged a sample", v)
			}
		}
	}
}

// Fewer than eight of one character is not a repeated run (four zeros, seven letters).
func TestShortRepeatedRunsBesideASampleAreNotJunk(t *testing.T) {
	sample := "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"
	for _, tail := range []string{":0000", ":aaaa", ":aaaaaaa", ":1111111", ":zzzzzzz", "-qqqq", ":Kkkkkkkk"} {
		if ptExtended(sample + tail) {
			t.Errorf("%q: fewer than eight of one character is judged junk", sample+tail)
		}
	}
	if !ptExtended(sample + ":aaaaaaaa") {
		t.Error("eight of one character beside a sample is no longer junk")
	}
}

// The jwt.io payload is published whole: a payload that merely starts with it is another
// payload.
func TestPublishedJWTPayloadIsMatchedWhole(t *testing.T) {
	payload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I" + "kpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	header := "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9"
	sig := ptRandom(77, 43)
	// old (rc.7): the published payload with any signature was a sample.
	// new (OR-89, F8-B1): only the whole published token is; a JWT that shares the payload
	// but carries another signature keeps v3.7.0's status.
	if ptExtended(header + "." + payload + "." + sig) {
		t.Error("a JWT with the published payload but another signature is judged a sample")
	}
	if !ptExtended(header + "." + payload + ".SflKxwRJSMeKKF2QT4fwp" + "MeJf36POk6yJV_adQssw5c") {
		t.Error("the jwt.io sample token is no longer a published sample")
	}
	for _, p := range []string{payload + "A", payload + "AAAA", "Q" + payload, payload + "Zk4Hq9xP2m"} {
		if ptExtended(header + "." + p + "." + sig) {
			t.Errorf("a payload that only contains the published one is a sample: %q", p)
		}
	}
}

// The jwt.io signature is published whole too: the same signature with anything added is
// another signature (a real token whose tail happens to start with the sample is not it).
func TestPublishedJWTSignatureIsMatchedWhole(t *testing.T) {
	header := "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9"
	payload := "eyJ1aWQiOiI0MiIsIn" + "JvbGUiOiJhZG1pbiJ9" // not the published payload
	sig := "SflKxwRJSMeKKF2QT4fwp" + "MeJf36POk6yJV_adQssw5c"
	// old (rc.7): the published signature with any payload was a sample.
	// new (OR-89, F8-B1): another payload is another token; the payload segment can carry
	// a real credential, so it keeps v3.7.0's status.
	if ptExtended(header + "." + payload + "." + sig) {
		t.Error("a JWT with the published signature but another payload is judged a sample")
	}
	for _, tail := range []string{"A", "Zk4Hq9x", "-0123456789", "AAAAAAAA"} {
		if ptExtended(header + "." + payload + "." + sig + tail) {
			t.Errorf("a signature that only starts with the published one is a sample (tail %q)", tail)
		}
	}
}

// A hand-typed sample often joins two interleaved runs (`1A2b...9I0j` then `K1l2...`: the
// parity of the digits shifts where the first run ends). Each run is a part of its own,
// at least six steps per offset; real text, or a run too short to be one, beside them
// makes the value not a sample. (Tier A: a documentation sample of this shape read INFO
// on rc.6 and WARN on the first whole-value build, which required one run for the segment.)
func TestJoinedInterleavedRunsAreSampleParts(t *testing.T) {
	for name, tc := range map[string]struct {
		v    string
		want bool
	}{
		"two runs, digits first":                                 {"ghp_" + "1A2b3C4d5E6f7G8h9I" + "0jK1l2M3n4O5p6Q7r8", true},
		"two runs glued after a prefix":                          {"sk_live_" + "1A2b3C4d5E6f7G8h9I" + "0jK1l2M3n4O5p6Q7r8", true},
		"two runs and a closed-list margin":                      {"ghp_" + "1A2b3C4d5E6f7G8h9I" + "0jK1l2M3n4O5p6Q7r8:changeme", true},
		"a run, then real text":                                  {"ghp_1A2b3C4d5E6f" + "7G8h9I0jKq8vZx2m", false},
		"real text, then a run":                                  {"ghp_Kq8vZx2m1A2b" + "3C4d5E6f7G8h9I0j", false},
		"a run, then a run too short":                            {"ghp_1A2b3C4d5E6" + "f7G8h9I0jK1l2M3", false},
		"a run, then one real character":                         {"ghp_" + "1A2b3C4d5E6f7G8h9I" + "0jK1l2M3n4O5p6Q7r8Z", false},
		"the digits turn around mid-run":                         {"ghp_1A2b3C4d" + "5E4f3G2h1I0j", false},
		"a stride-three run":                                     {"ghp_1Aa2Bb3Cc4D" + "d5Ee6Ff7Gg8Hh9Ii", true},
		"two stride-three runs":                                  {"ghp_" + "1Aa2Bb3Cc4Dd5Ee6Ff7Gg8" + "HhIi1Jj2Kk3Ll4Mm5Nn6Oo", true},
		"a run of four elements per offset, then a repeated run": {"ghp_1A2b3C4dxxxxxxxxxx", false},
		"the last letter of the run starts a listed word":        {"ghp_1a2b3c4d5e6f7g8h9i0j1k2l3mock", true},
		"a run of five elements per offset":                      {"ghp_1A2b3C4d5E", false},
		"a run of six elements per offset":                       {"ghp_1A2b3C4d5E6f", true},
	} {
		if got := ptExtended(tc.v); got != tc.want {
			t.Errorf("%s: Extended = %v, want %v (%q)", name, got, tc.want, tc.v)
		}
	}
}
