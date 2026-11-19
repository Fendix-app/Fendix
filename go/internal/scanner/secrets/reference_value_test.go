package secrets

// NEW-E1 (Round 6 closure, owner ruling OR-85, option (a)).
//
// The reference check used to read the WHOLE LINE: a credential was dropped
// when anything else on its line carried a secrets-manager resource name
// (arn:aws:secretsmanager:, arn:aws:ssm:, arn:aws:kms:, rds!db-, rds!cluster-,
// projects/). A GitHub token followed by a link to a GitHub "projects" board
// produced no finding, every analyzer ok, exit 0: a false clean that needed no
// adversary. The rule is now value-scoped: only the credential's own value can
// make it a reference.
//
// These tests pin both halves. A reference prefix ANYWHERE ELSE on the line,
// in every position a real file puts one, must not suppress a credential; and a
// value that IS a reference stays suppressed.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// e1Prefixes carries every reference prefix the rule knows, one realistic resource name
// each, plus an upper-case spelling (the check is case-insensitive).
var e1Prefixes = []struct{ name, text string }{
	{"secretsmanager", "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"},
	{"ssm", "arn:aws:ssm:us-east-1:123456789012:parameter/prod/token"},
	{"kms", "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
	{"rds-db", "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"},
	{"rds-cluster", "rds!cluster-403f5acc-6752-4edd-a4a9-339a8395f134"},
	{"projects", "projects/my-proj/secrets/db-password/versions/latest"},
	{"projects-url", "https://github.com/orgs/acme-corp/projects/4"},
	{"upper", "ARN:AWS:SECRETSMANAGER:EU-CENTRAL-1:123456789012:SECRET:PROD/DB-ABCDEF PROJECTS/X"},
}

// e1Cred is one real-format credential that the scanner reports in its bare
// form. member is the same credential as one JSON member (empty when the rule's
// regex has no JSON spelling).
type e1Cred struct {
	name, id string
	stmt     string
	member   string
}

var e1Creds = []e1Cred{
	{"github", "SEC-GITHUB_TOKEN", `GH_PAT = "ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`, `"GH_PAT":"ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`},
	{"aws-id", "SEC-AWS_ACCESS_KEY", `AWS_ID = "AKIA` + `J4Q7ZP2VNW5XM3RT"`, `"AWS_ID":"AKIA` + `J4Q7ZP2VNW5XM3RT"`},
	{"aws-secret", "SEC-AWS_SECRET_KEY", `aws_secret_access_key = "nT4pQ8vX2bK7mL1zR9cY` + `6wJ3hF5dG0sA/B+eU2iO"`, `"aws_secret_access_key":"nT4pQ8vX2bK7mL1zR9cY` + `6wJ3hF5dG0sA/B+eU2iO"`},
	{"stripe", "SEC-STRIPE_LIVE_KEY", `STRIPE = "sk_live_` + `51NzQ2rB7mK4` + `vT9xW3pY8cL0d"`, `"STRIPE":"sk_live_` + `51NzQ2rB7mK4` + `vT9xW3pY8cL0d"`},
	{"slack", "SEC-SLACK_TOKEN", `SLACK = "xoxb-` + `2847561930-5738291046-Q` + `pLmZxCvBnAsDfGhJkLwErTy"`, `"SLACK":"xoxb-` + `2847561930-5738291046-Q` + `pLmZxCvBnAsDfGhJkLwErTy"`},
	{"google", "SEC-GOOGLE_API_KEY", `MAPS = "AIzaSyC4mQ9vK2xT7pL` + `1wN8bZ5yR3zA6hD0eFgH"`, `"MAPS":"AIzaSyC4mQ9vK2xT7pL` + `1wN8bZ5yR3zA6hD0eFgH"`},
	{"jwt", "SEC-JWT_TOKEN", `JWT = "eyJhbGciOiJIUzI1Ni` + `IsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxM` + `jM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwp` + `MeJf36POk6yJV_adQssw5c"`, `"JWT":"eyJhbGciOiJIUzI1Ni` + `IsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxM` + `jM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwp` + `MeJf36POk6yJV_adQssw5c"`},
	{"password", "SEC-HARDCODED_PASSWORD", `password = "Tr0ub4dor&3-xylophone"`, ""},
	{"api-key", "SEC-GENERIC_API_KEY", `api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"`, ""},
	{"secret-config", "SEC-HARDCODED_SECRET_CONFIG", `app.secret_key = "F12Zr47jyXR_` + `XatHjmMLwfKT"`, `"secret_key": "F12Zr47jyXR_` + `XatHjmMLwfKT"`},
	{"db-url", "SEC-DB_CONNECTION_STRING", `DB = "postgresql://admin:S3cretPw9xQ@db.internal:5432/app"`, ""},
}

// e1Position wraps one credential statement and one reference text into a line.
// jsonOnly positions need the credential's JSON member spelling.
type e1Position struct {
	name     string
	file     string
	jsonOnly bool
	build    func(c e1Cred, noise string) string
}

var e1Positions = []e1Position{
	{name: "hash-comment", file: "a.py", build: func(c e1Cred, n string) string {
		return c.stmt + "  # see " + n
	}},
	{name: "slash-comment", file: "a.js", build: func(c e1Cred, n string) string {
		return c.stmt + "; // " + n
	}},
	{name: "block-comment", file: "a.js", build: func(c e1Cred, n string) string {
		return c.stmt + "; /* " + n + " */"
	}},
	{name: "block-comment-before", file: "a.js", build: func(c e1Cred, n string) string {
		return "/* " + n + " */ " + c.stmt + ";"
	}},
	{name: "url-after", file: "a.js", build: func(c e1Cred, n string) string {
		return c.stmt + "; docs = 'https://console.example.test/secret-manager?ref=" + n + "'"
	}},
	{name: "second-assignment-after", file: "a.py", build: func(c e1Cred, n string) string {
		return c.stmt + "; secret_ref = '" + n + "'"
	}},
	{name: "second-assignment-before", file: "a.py", build: func(c e1Cred, n string) string {
		return "secret_ref = '" + n + "'; " + c.stmt
	}},
	{name: "json-sibling-after", file: "a.json", jsonOnly: true, build: func(c e1Cred, n string) string {
		return `{ ` + c.member + `, "secret_ref": "` + n + `" }`
	}},
	{name: "json-sibling-before", file: "a.json", jsonOnly: true, build: func(c e1Cred, n string) string {
		return `{ "secret_ref": "` + n + `", ` + c.member + ` }`
	}},
}

// e1Findings returns the finding IDs per 1-based line of file.
func e1Findings(t *testing.T, fs []evidence.Evidence, file string) map[int][]string {
	t.Helper()
	out := map[int][]string{}
	for _, f := range fs {
		if !strings.HasPrefix(f.Endpoint, file+":") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(f.Endpoint, file+":"))
		if err != nil {
			t.Fatalf("endpoint %q: %v", f.Endpoint, err)
		}
		out[n] = append(out[n], f.ID)
	}
	for _, ids := range out {
		sort.Strings(ids)
	}
	return out
}

func e1Has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// TestNewE1_PrefixElsewhereOnLineDoesNotSuppressCredential: for every
// credential rule, in every position a file puts a resource name, a credential
// is reported exactly as it is without the resource name.
func TestNewE1_PrefixElsewhereOnLineDoesNotSuppressCredential(t *testing.T) {
	for _, pos := range e1Positions {
		for _, c := range e1Creds {
			if pos.jsonOnly && c.member == "" {
				continue
			}
			t.Run(pos.name+"/"+c.name, func(t *testing.T) {
				dir := t.TempDir()
				var lines []string
				for _, p := range e1Prefixes {
					lines = append(lines, pos.build(c, p.text))
				}
				writeFile(t, dir, pos.file, strings.Join(lines, "\n")+"\n")
				// The control: the bare credential is a finding, so a miss
				// below is the resource name's doing and nothing else.
				writeFile(t, dir, "bare."+pos.file, c.stmt+"\n")
				if pos.jsonOnly {
					writeFile(t, dir, "bare."+pos.file, "{ "+c.member+" }\n")
				}
				fs, err := Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if !e1Has(e1Findings(t, fs, "bare."+pos.file)[1], c.id) {
					t.Fatalf("control: the bare credential did not report %s: %v", c.id, endpointsOf(fs))
				}
				got := e1Findings(t, fs, pos.file)
				for i, p := range e1Prefixes {
					if !e1Has(got[i+1], c.id) {
						t.Errorf("%s dropped by a %q resource name at position %s (line %d: %s); findings on the line: %v",
							c.id, p.name, pos.name, i+1, lines[i], got[i+1])
					}
				}
			})
		}
	}
}

// TestNewE1_MinifiedLineFarFromReference: the realistic shape. A bundle is one
// line of tens of kilobytes; a Firebase or GCP client in it carries
// "projects/" strings, and a hard-coded token sits tens of kilobytes away.
func TestNewE1_MinifiedLineFarFromReference(t *testing.T) {
	filler := func(n int, tag string) string {
		var b strings.Builder
		for b.Len() < n {
			fmt.Fprintf(&b, "var %s%d=function(e){return e+%d};", tag, b.Len(), b.Len()%7)
		}
		return b.String()
	}
	for _, c := range e1Creds {
		for _, order := range []string{"token-first", "reference-first"} {
			t.Run(order+"/"+c.name, func(t *testing.T) {
				dir := t.TempDir()
				var lines []string
				for _, p := range e1Prefixes {
					ref := `var r="` + p.text + `";`
					switch order {
					case "token-first":
						lines = append(lines, `!function(){`+c.stmt+`;`+filler(30000, "a")+ref+filler(2000, "b")+`}();`)
					default:
						lines = append(lines, `!function(){`+ref+filler(30000, "a")+c.stmt+`;`+filler(2000, "b")+`}();`)
					}
				}
				writeFile(t, dir, "bundle.min.js", strings.Join(lines, "\n")+"\n")
				fs, err := Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				got := e1Findings(t, fs, "bundle.min.js")
				for i, p := range e1Prefixes {
					if !e1Has(got[i+1], c.id) {
						t.Errorf("%s in a minified line dropped by a distant %q resource name; line %d has %v", c.id, p.name, i+1, got[i+1])
					}
				}
			})
		}
	}
}

// TestNewE1_PrivateKeyKeepsItsRestOfLine: the PEM of a one-line service-account
// JSON is everything after the header, so a sibling member after it is on the
// credential's own line. It must not suppress the key. A header has no value
// that could be a reference.
func TestNewE1_PrivateKeyKeepsItsRestOfLine(t *testing.T) {
	dir := t.TempDir()
	const pem = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk` + `qhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n`
	var lines []string
	for _, p := range e1Prefixes {
		lines = append(lines,
			`{"private_key":"`+pem+`","kms_ref":"`+p.text+`"}`,
			`{"kms_ref":"`+p.text+`","private_key":"`+pem+`"}`,
			`# `+p.text+` -----BEGIN RSA PRIVATE KEY-----`,
			`-----BEGIN EC PRIVATE KEY----- `+p.text,
		)
	}
	writeFile(t, dir, "sa.json", strings.Join(lines, "\n")+"\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := e1Findings(t, fs, "sa.json")
	for i, l := range lines {
		if !e1Has(got[i+1], "SEC-PRIVATE_KEY") {
			t.Errorf("PRIVATE_KEY dropped on line %d (%.70s...); findings: %v", i+1, l, got[i+1])
		}
	}
}

// TestNewE1_E1Pair is the reproduction from the decision package
// (R6D/package-evidence/e1-pair): the same token with and without a GitHub
// projects link in a trailing comment. Both must report the same finding.
func TestNewE1_E1Pair(t *testing.T) {
	const tok = `GH_PAT = "ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`
	dir := t.TempDir()
	writeFile(t, dir, "without/config.py", tok+"\n")
	writeFile(t, dir, "with/config.py", tok+"  # https://github.com/orgs/acme-corp/projects/4\n")
	without, err := Scan(context.Background(), dir+"/without")
	if err != nil {
		t.Fatal(err)
	}
	with, err := Scan(context.Background(), dir+"/with")
	if err != nil {
		t.Fatal(err)
	}
	if len(without) != 1 || without[0].ID != "SEC-GITHUB_TOKEN" {
		t.Fatalf("control: want one SEC-GITHUB_TOKEN without the link, got %v", endpointsOf(without))
	}
	if len(with) != 1 || with[0].ID != "SEC-GITHUB_TOKEN" {
		t.Fatalf("a GitHub-projects link in a comment hid the token: want one SEC-GITHUB_TOKEN, got %v", endpointsOf(with))
	}
	if with[0].Severity != without[0].Severity || with[0].Endpoint != without[0].Endpoint {
		t.Errorf("same finding expected: with=%s/%s without=%s/%s", with[0].Severity, with[0].Endpoint, without[0].Severity, without[0].Endpoint)
	}
}

// TestNewE1_ValueThatIsAReferenceStaysSuppressed: the original purpose (B1) is
// intact. Each case is a line that a registry pattern matches, so the
// suppression is what is under test, and each has a control with a real-format
// value in place of the reference that is reported.
func TestNewE1_ValueThatIsAReferenceStaysSuppressed(t *testing.T) {
	cases := []struct {
		name, id, line, control string
	}{
		{"password-rds-db", "SEC-HARDCODED_PASSWORD", `password = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"`, `password = "Tr0ub4dor&3-xylophone"`},
		{"password-rds-cluster", "SEC-HARDCODED_PASSWORD", `password = "rds!cluster-403f5acc-6752-4edd-a4a9-339a8395f134"`, `password = "Tr0ub4dor&3-xylophone"`},
		{"password-ssm", "SEC-HARDCODED_PASSWORD", `password = "arn:aws:ssm:us-east-1:123456789012:parameter/prod/db"`, `password = "Tr0ub4dor&3-xylophone"`},
		{"password-kms", "SEC-HARDCODED_PASSWORD", `pwd: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd'`, `pwd: 'Tr0ub4dor&3-xylophone'`},
		{"secret-config-arn", "SEC-HARDCODED_SECRET_CONFIG", `secret_key = "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"`, `secret_key = "F12Zr47jyXR_` + `XatHjmMLwfKT"`},
		{"secret-config-arn-json", "SEC-HARDCODED_SECRET_CONFIG", `{ "secret_key": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf" }`, `{ "secret_key": "F12Zr47jyXR_` + `XatHjmMLwfKT" }`},
		{"secret-config-upper", "SEC-HARDCODED_SECRET_CONFIG", `SECRET_KEY = "ARN:AWS:SECRETSMANAGER:EU-CENTRAL-1:123456789012:SECRET:PROD/DB-ABCDEF"`, `SECRET_KEY = "F12Zr47jyXR_` + `XatHjmMLwfKT"`},
		{"api-key-gcp", "SEC-GENERIC_API_KEY", `api_key = "projects/my-proj/secrets/db-password/versions/latest"`, `api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"`},
		{"client-secret-gcp", "SEC-GENERIC_API_KEY", `client_secret: 'projects/123456/secrets/oauth/versions/1'`, `client_secret: 'k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "ref.py", c.line+"\n")
			writeFile(t, dir, "control.py", c.control+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if !e1Has(e1Findings(t, fs, "control.py")[1], c.id) {
				t.Fatalf("control: %q must report %s: %v", c.control, c.id, endpointsOf(fs))
			}
			if got := e1Findings(t, fs, "ref.py"); len(got) != 0 {
				t.Errorf("a value that is a reference must stay suppressed: %q reported %v", c.line, got)
			}
		})
	}
}

// TestNewE1_ReferenceSiblingDoesNotHideCredentialAndViceVersa: on one line, the
// reference-valued member stays suppressed and the credential-valued member is
// reported. The decision is per value, not per line.
func TestNewE1_ReferenceSiblingDoesNotHideCredentialAndViceVersa(t *testing.T) {
	dir := t.TempDir()
	const gh = `"GH_PAT": "ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`
	const arn = `"secret_key": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"`
	lines := []string{
		`{ ` + arn + `, ` + gh + ` }`,
		`{ ` + gh + `, ` + arn + ` }`,
		`password = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"; api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"`,
		`api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"; password = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"`,
		// Controls: the same shapes with a real value in the reference's place
		// report both members, so the suppressed one above is the reference's
		// doing and nothing else.
		`{ "secret_key": "F12Zr47jyXR_` + `XatHjmMLwfKT", ` + gh + ` }`,
		`password = "Tr0ub4dor&3-xylophone"; api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"`,
	}
	writeFile(t, dir, "mixed.py", strings.Join(lines, "\n")+"\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := e1Findings(t, fs, "mixed.py")
	want := map[int][]string{
		1: {"SEC-GITHUB_TOKEN"},
		2: {"SEC-GITHUB_TOKEN"},
		3: {"SEC-GENERIC_API_KEY"},
		4: {"SEC-GENERIC_API_KEY"},
		5: {"SEC-GITHUB_TOKEN", "SEC-HARDCODED_SECRET_CONFIG"},
		6: {"SEC-GENERIC_API_KEY", "SEC-HARDCODED_PASSWORD"},
	}
	for n, w := range want {
		if fmt.Sprint(got[n]) != fmt.Sprint(w) {
			t.Errorf("line %d: want exactly %v, got %v", n, w, got[n])
		}
	}
}

// ── C1-1 (orchestrator correction, inside NEW-E1) ──────────────────────────
//
// A value is a reference only when the WHOLE value is a well-formed reference,
// anchored at both ends. A value that merely CONTAINS a reference prefix, or is
// one followed by other text, is a credential: `password = "projects/hunter2hunter2"`
// is a real password that happens to start like a resource name.

// A value that contains one of the six prefixes without being a reference.
func TestNewE1_ValueThatOnlyContainsAPrefixIsReported(t *testing.T) {
	cases := []struct{ name, line string }{
		// The prefix, then text that makes it something other than a reference.
		{"projects-no-secrets-segment", `password = "projects/hunter2hunter2"`},
		{"projects-secrets-then-junk", `password = "projects/p/secrets/s/` + `versions/1xyzJunkJunk"`},
		{"projects-trailing-text", `password = "projects/p/secrets/s hunter2hunter2"`},
		{"rds-db-not-a-uuid", `password = "rds!db-hunter2hunter2"`},
		{"rds-cluster-not-a-uuid", `password = "rds!cluster-nota` + `uuid-Hunter2"`},
		{"rds-db-uuid-then-junk", `password = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134-hunter2"`},
		{"secretsmanager-trailing-text", `password = "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf hunter2"`},
		{"secretsmanager-bad-account", `password = "arn:aws:secretsmanager:eu-central-1:12345:secret:prod/db-AbCdEf"`},
		{"secretsmanager-no-resource", `password = "arn:aws:secretsmanager:eu-central-1:123456789012:hunter2hunter2"`},
		{"ssm-trailing-secret", `password = "arn:aws:ssm:us-east-1:123456789012:parameter/prod/db,Hunter2Hunter2"`},
		{"ssm-wrong-resource-type", `password = "arn:aws:ssm:us-east-1:123456789012:hunter2hunter2"`},
		{"kms-not-a-key-or-alias", `password = "arn:aws:kms:us-east-1:123456789012:Hunter2Hunter2"`},
		{"kms-key-then-junk", `password = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd Hunter2"`},
		// The prefix in the middle or glued to the front of something else.
		{"prefix-glued-to-the-front", `password = "Xrds!db-403f5acc-6752-4edd-a4a9-339a8395f134"`},
		{"projects-glued-to-the-front", `password = "Zprojects/p/secr` + `ets/s/versions/1"`},
		{"prefix-mid-string-arn", `password = "my-Hunter2-arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd"`},
		{"prefix-mid-string-projects", `password = "Hunter2/projec` + `ts/p/secrets/s"`},
		{"prefix-mid-string-rds", `password = "Hunter2rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"`},
		{"unknown-partition", `password = "arn:evil:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"`},
		// A real token with a prefix glued to its front: the credential is the
		// whole value, and it is reported by the generic rule too.
		{"token-behind-projects", `secret_key = "projects/ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`},
		{"token-behind-rds", `secret_key = "rds!db-ghp_` + `p7Z3yolXy7wa2HziUY` + `LDxN8oRSUN8x12T7xe"`},
		{"api-key-behind-projects", `api_key = "projects/MZGrtj2Ea` + `RPTf7oTvDBEqb00yDPV"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "c.py", c.line+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := e1Findings(t, fs, "c.py")[1]; len(got) == 0 {
				t.Errorf("%s: a value that is not a reference was suppressed: %s", c.name, c.line)
			}
		})
	}
}

// A well-formed reference, in every shape the rule is for, stays suppressed.
func TestNewE1_WellFormedReferencesStaySuppressed(t *testing.T) {
	refs := []string{
		"arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-403f5acc-6752-4edd-a" + "4a9-339a8395f134-Xyz123",
		"arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:prod/db-AbCdEf",
		"arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:prod/db-AbCdEf",
		"arn:aws:ssm:us-east-1:123456789012:parameter/prod/db/password",
		"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab",
		"arn:aws:kms:us-east-1:123456789012:alias/prod-db",
		"arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:prod/db-AbCdEf",
		"rds!db-403f5acc-6752-4edd-a4a9-339a8395f134",
		"rds!cluster-403f5acc-6752-4edd-a4a9-339a8395f134",
		"projects/my-proj/secrets/db-password",
		"projects/my-proj/secrets/db-password/versions/latest",
		"projects/123456/secrets/oauth/versions/7",
		"projects/p/secrets/s/versions/1",
		"projects/my-proj/locations/europe-west1/secrets/db-password/versions/3",
	}
	for _, rule := range []string{`password = "%s"`, `secret_key = "%s"`} {
		for i, r := range refs {
			t.Run(fmt.Sprintf("%s/%02d-%s", strings.SplitN(rule, " ", 2)[0], i, strings.SplitN(r, ":", 2)[0]), func(t *testing.T) {
				dir := t.TempDir()
				line := fmt.Sprintf(rule, r)
				writeFile(t, dir, "c.py", line+"\n")
				control := strings.Replace(line, r, "Tr0ub4dor&3-xylophone", 1)
				writeFile(t, dir, "ctl.py", control+"\n")
				fs, err := Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if len(e1Findings(t, fs, "ctl.py")[1]) == 0 {
					t.Fatalf("control: %q must be reported", control)
				}
				if got := e1Findings(t, fs, "c.py"); len(got) != 0 {
					t.Errorf("a well-formed reference was reported: %s -> %v", line, got)
				}
			})
		}
	}
}

// A well-formed reference with text around it is not a reference, and neither
// is a reference with whitespace trimmed around it hiding a second value.
func TestNewE1_ReferenceAnchoredAtBothEnds(t *testing.T) {
	const arn = "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"
	for name, v := range map[string]string{
		"leading text":  "Hunter2Hunter2:" + arn,
		"trailing text": arn + ":Hunter2Hunter2!",
		"two refs":      arn + "," + arn,
		"leading space": "x " + arn,
	} {
		t.Run(name, func(t *testing.T) {
			if isReferenceValue(v) {
				t.Errorf("%q taken for a reference", v)
			}
		})
	}
	if !isReferenceValue("  " + arn + "  ") {
		t.Error("surrounding whitespace must not stop a reference being a reference")
	}
}
