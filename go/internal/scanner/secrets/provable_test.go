package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// Credentials provable offline (RC-10b): a GitHub checksum, a PEM body that
// parses, an AWS pair. Every other value is not provable.

func ghToken(body30 string) string {
	return "ghp_" + body30 + base62Checksum(crc32.ChecksumIEEE([]byte(body30)))
}

func TestGithubChecksumValid(t *testing.T) {
	valid := []string{
		"ghp_" + "939WtxKhJoVW1aucqQ" + "iORTI3zKRmGx4RaDXs",
		"gho_" + "OWpeNk2NSCXDODhoU2" + "SOyLQzMWLYpu1lHHFj",
		ghToken("DyDePsxLWfKa0WC" + "i0mXWeaNWyFaXRZ"),
	}
	for _, v := range valid {
		if !githubChecksumValid(v) {
			t.Errorf("%q: a checksum-valid token was not recognised", v)
		}
	}
	invalid := map[string]string{
		"right shape, wrong checksum": "ghp_" + "bUid1uhY2HKVrWfQkw" + "LoZufvsnPPElS4YRQB",
		"checksum off by one":         valid[0][:len(valid[0])-1] + "t",
		"short":                       "ghp_939WtxKhJoVW1" + "aucqQiORTI3zKRmGx",
		"not a token":                 "password123",
		"synthetic body, valid sum":   ghToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"sequential body, valid sum":  ghToken("abcdefghijklmnopqrstuvwxyz0123"),
	}
	for name, v := range invalid {
		if githubChecksumValid(v) {
			t.Errorf("%s: %q was taken for provable", name, v)
		}
	}
}

func ecPEMKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func TestPEMBodyParses(t *testing.T) {
	key := ecPEMKey(t)
	lines := strings.Split(strings.TrimRight(key, "\n"), "\n")
	if !pemBodyParses(lines, 0) {
		t.Fatalf("a real key did not parse:\n%s", key)
	}
	// The same key as one JSON string, \n-escaped (a service-account file).
	oneLine := `{"private_key": "` + strings.ReplaceAll(strings.TrimRight(key, "\n"), "\n", `\n`) + `\n"}`
	if !pemBodyParses([]string{oneLine}, 0) {
		t.Errorf("a one-line JSON key did not parse")
	}
	// Surrounded by prose.
	prose := append([]string{"Generate a key:", "```"}, append(lines, "```")...)
	if !pemBodyParses(prose, 2) {
		t.Errorf("a key inside a code fence did not parse")
	}
	notKeys := map[string][]string{
		"elided":      {"-----BEGIN RSA PRIVATE KEY-----", "...", "-----END RSA PRIVATE KEY-----"},
		"header only": {"The file starts with -----BEGIN RSA PRIVATE KEY-----", "and ends with the END line."},
		"garbage":     {"-----BEGIN PRIVATE KEY-----", "MIIEvQIBADANBgkqhkiG9w0BAQ" + "EFAASCBKcwggSjAgEAAoIBAQ==", "-----END PRIVATE KEY-----"},
		"not base64":  {"-----BEGIN PRIVATE KEY-----", "this is *not* base64 !!!", "-----END PRIVATE KEY-----"},
		"truncated":   append(append([]string{}, lines[:2]...), "-----END EC PRIVATE KEY-----"),
	}
	for name, ls := range notKeys {
		if pemBodyParses(ls, 0) {
			t.Errorf("%s: taken for a key that parses", name)
		}
	}
}

func TestAWSPairProvable(t *testing.T) {
	id := `export AWS_ACCESS_KEY_ID=AKIA` + `XNBYXL2PFSVNFHDL`
	sk := `aws_secret_access_key = "cGRXMHvXJBZgM8OQso9u` + `9EPGO+ZSwQgsydGc8Oop"`
	if !awsPairProvable([]string{id, sk}, 0, "AWS_ACCESS_KEY") || !awsPairProvable([]string{id, sk}, 1, "AWS_SECRET_KEY") {
		t.Error("a key id with its secret on the next line is a provable pair")
	}
	if !awsPairProvable([]string{id, "", "", sk}, 0, "AWS_ACCESS_KEY") {
		t.Error("a pair three lines apart is provable")
	}
	if awsPairProvable([]string{id, "", "", "", sk}, 0, "AWS_ACCESS_KEY") {
		t.Error("a pair four lines apart is not")
	}
	if awsPairProvable([]string{id}, 0, "AWS_ACCESS_KEY") {
		t.Error("a key id alone is not provable")
	}
	exID := `export AWS_ACCESS_KEY_ID=AKIA` + `IOSFODNN7EXAMPLE`
	exSK := `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	if awsPairProvable([]string{exID, exSK}, 0, "AWS_ACCESS_KEY") {
		t.Error("AWS's documented example pair is a sample, not provable")
	}
	if awsPairProvable([]string{id, exSK}, 0, "AWS_ACCESS_KEY") {
		t.Error("a real-looking id beside a sample secret is not a pair")
	}
}

func scanOne(t *testing.T, path, content string) []evidence.Evidence {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, path, content)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return fs
}

func evidenceByRule(fs []evidence.Evidence, rule string) []evidence.Evidence {
	var out []evidence.Evidence
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// The scanner stamps OfflineProvable on documentation findings only, and
// InDoc/SyntheticValue ride with them.
func TestScanStampsProvabilityOnDocumentationOnly(t *testing.T) {
	key := ecPEMKey(t)
	tok := "ghp_" + "939WtxKhJoVW1aucqQ" + "iORTI3zKRmGx4RaDXs"
	aws := "export AWS_ACCESS_KEY_ID=AKIA" + "XNBYXL2PFSVNFHDL\naws_secret_access_key = \"cGRXMHvXJBZgM8OQso9u" + "9EPGO+ZSwQgsydGc8Oop\"\n"
	for _, doc := range []string{"README.md", "docs/guide.rst", "docs/notes.txt"} {
		fs := scanOne(t, doc, "Use this:\n"+key+"\n"+tok+"\n"+aws)
		for _, rule := range []string{"secrets/PRIVATE_KEY", "secrets/GITHUB_TOKEN", "secrets/AWS_ACCESS_KEY", "secrets/AWS_SECRET_KEY"} {
			got := evidenceByRule(fs, rule)
			if len(got) == 0 {
				t.Errorf("%s: no %s finding", doc, rule)
			}
			for _, f := range got {
				if !f.OfflineProvable {
					t.Errorf("%s: %s at %s is provable offline and was not marked", doc, rule, f.Endpoint)
				}
			}
		}
	}
	// The same bytes in source: nothing is computed, nothing is marked.
	fs := scanOne(t, "src/config.py", "KEY = '''"+key+"'''\nT = '"+tok+"'\n"+aws)
	for _, f := range fs {
		if f.OfflineProvable {
			t.Errorf("%s at %s marked provable outside documentation", f.RuleID, f.Endpoint)
		}
	}
	// A deployable config under docs/ is not documentation: no marking.
	fs = scanOne(t, "docs/nacos/application.yaml", "token: "+tok+"\n")
	for _, f := range fs {
		if f.OfflineProvable {
			t.Errorf("%s in docs/nacos/application.yaml marked provable: it is not documentation", f.RuleID)
		}
	}
}

func TestScanDocumentationNotProvable(t *testing.T) {
	fs := scanOne(t, "README.md", "ghp_"+"bUid1uhY2HKVrWfQkw"+"LoZufvsnPPElS4YRQB\n-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\nexport AWS_ACCESS_KEY_ID=AKIA"+"Y6FL2L5SP7ZB565L\n")
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range fs {
		if f.OfflineProvable {
			t.Errorf("%s at %s marked provable: a bad checksum, an elided key and a lone key id are not", f.RuleID, f.Endpoint)
		}
		if !f.OfflineProvable && f.Severity == "" {
			t.Errorf("finding lost its severity")
		}
	}
}

func TestScanSyntheticValueFlag(t *testing.T) {
	fs := scanOne(t, "src/a.py", "password = \"password123\"\napi_key = \"MZGrtj2EaRPTf7"+"oTvDBEqb00yDPV\"\nFAKE_API_KEY = \"jACk8FkYZFnP7A"+"b5DSDVe0Qq7wBe\"\n")
	byLine := map[string]evidence.Evidence{}
	for _, f := range fs {
		byLine[f.Endpoint] = f
	}
	if f := byLine["src/a.py:1"]; !f.SyntheticValue || !f.Placeholder {
		t.Errorf("password123: SyntheticValue=%v Placeholder=%v, want both", f.SyntheticValue, f.Placeholder)
	}
	if f := byLine["src/a.py:2"]; f.SyntheticValue || f.Placeholder {
		t.Errorf("a random api key: SyntheticValue=%v Placeholder=%v, want neither", f.SyntheticValue, f.Placeholder)
	}
	// A FAKE_ name is a placeholder (confidence evidence) but not VALUE evidence.
	if f := byLine["src/a.py:3"]; f.SyntheticValue || !f.Placeholder {
		t.Errorf("FAKE_ name with a random value: SyntheticValue=%v Placeholder=%v, want only Placeholder", f.SyntheticValue, f.Placeholder)
	}
}
