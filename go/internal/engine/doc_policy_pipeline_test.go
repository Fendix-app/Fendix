package engine

// RC-10b (d) (Round 6 closure, owner ruling OR-85): how a credential in
// documentation scores.
//
// Since ce972bb the secrets scanner reads every text file, and documentation
// scored as production code: +30 "deterministic detection", so a sample
// credential in a README BLOCKed. The approved rule is evidence-based:
//
//   - a credential in documentation earns no deterministic-detection weight,
//     unless it is provable offline: a checksum-valid GitHub token, a private
//     key whose body parses, an AWS key pair. Those keep BLOCK;
//   - any other real-format value (Stripe, Slack, Google, JWT, database URL,
//     npm) is a WARN;
//   - a value that is demonstrably synthetic goes lower, to INFO;
//   - documentation is decided by the FILE, not by a directory name alone: a
//     deployable config (a Nacos .yaml or .properties under docs/) is not
//     documentation, and neither is a file named for what it holds
//     (credentials.txt);
//   - the common-placeholder list and the extended synthetic classifier apply
//     in every file: a sample value is a sample wherever it is written.
//
// These tests scan real files with the real secrets scanner and run the real
// finalization (decision included), so they pin the behaviour end to end.
// Every value is fabricated (the RC-10 fixture matrix's values).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// the matrix's values, by id (fixtures/values.json of the RC-10 analysis).
const (
	vGHProvable   = "ghp_" + "939WtxKhJoVW1aucqQ" + "iORTI3zKRmGx4RaDXs" // checksum valid
	vGHRandom     = "ghp_" + "bUid1uhY2HKVrWfQkw" + "LoZufvsnPPElS4YRQB" // right format, checksum invalid
	vGHAlternate  = "ghp_" + "1A2b3C4d5E6f7G8h9I" + "0j1K2l3M4n5O6p7Q8r"
	vGHXs         = "ghp_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	vGHSequential = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	vAWSID        = "AKIA" + "XNBYXL2PFSVNFHDL"
	vAWSSecret    = "cGRXMHvXJBZgM8OQso9u" + "9EPGO+ZSwQgsydGc8Oop"
	vAWSIDAlone   = "AKIA" + "Y6FL2L5SP7ZB565L"
	vAWSExampleID = "AKIA" + "IOSFODNN7EXAMPLE"
	vAWSExampleSk = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	vStripe       = "sk_live_" + "819QiMBRbjhU" + "gnaunrIqoXhi"
	vStripeDoc    = "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc" // Stripe's published example body
	vSlack        = "xoxb-" + "755729417849-880746575526" + "5-C4iLF51u3NoEvbIITuELkgqf"
	vSlackSeq     = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	vGoogle       = "AIzaHcUNmwYizom5maG" + "PcUdUQbcz9NOuujbzVBB"
	vGoogleX      = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	vDB           = "postgres://svc_reports:kRUv6bJ9uSn2yWrKwAjm@db-prod-3.internal.acme-corp.net:5432/reports"
	vDBChangeme   = "mysql://root:changeme@127.0.0.1:3306/app"
	vNPM          = "npm_ykbJyQrihjc4Q5iz" + "4DYAWDoa9g6gsL1z7uhL"
	vNPMXs        = "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

type docCred struct {
	name string
	// body returns the file content holding the credential.
	body func(t *testing.T) string
	// doc is the status in documentation; src in an ordinary source file.
	doc, src string
}

func docLine(s string) func(*testing.T) string { return func(*testing.T) string { return s + "\n" } }

func ecPEM(t *testing.T) string {
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

var docCreds = []docCred{
	// Provable offline: they keep BLOCK in documentation.
	{"github-checksum-valid", docLine(`export GITHUB_TOKEN=` + vGHProvable), "BLOCK", "BLOCK"},
	{"aws-key-pair", docLine("export AWS_ACCESS_KEY_ID=" + vAWSID + "\naws_secret_access_key = \"" + vAWSSecret + "\""), "BLOCK", "BLOCK"},
	{"private-key-that-parses", ecPEM, "BLOCK", "BLOCK"},
	// Real-format but not provable offline: WARN in documentation, BLOCK in source.
	{"github-checksum-invalid", docLine(`export GITHUB_TOKEN=` + vGHRandom), "WARN", "BLOCK"},
	{"aws-key-alone", docLine("export AWS_ACCESS_KEY_ID=" + vAWSIDAlone), "WARN", "BLOCK"},
	{"stripe", docLine(`STRIPE_KEY = "` + vStripe + `"`), "WARN", "BLOCK"},
	{"slack", docLine(`SLACK_TOKEN = "` + vSlack + `"`), "WARN", "BLOCK"},
	{"google", docLine(`MAPS_KEY = "` + vGoogle + `"`), "WARN", "BLOCK"},
	{"database-url", docLine(`DATABASE_URL = "` + vDB + `"`), "WARN", "BLOCK"},
	{"npm", docLine(`NPM_TOKEN = "` + vNPM + `"`), "WARN", "BLOCK"},
	{"password-random", docLine(`password = "UYOo0f52uLnk#9!"`), "WARN", "BLOCK"},
	// Demonstrably synthetic: INFO in documentation, WARN (fixture-shaped) in source.
	{"github-alternating", docLine(`export GITHUB_TOKEN=` + vGHAlternate), "INFO", "WARN"},
	{"github-xs", docLine(`export GITHUB_TOKEN=` + vGHXs), "INFO", "WARN"},
	{"github-sequential", docLine(`export GITHUB_TOKEN=` + vGHSequential), "INFO", "WARN"},
	{"aws-documented-example", docLine("export AWS_ACCESS_KEY_ID=" + vAWSExampleID + "\naws_secret_access_key = \"" + vAWSExampleSk + "\""), "INFO", "WARN"},
	{"stripe-published-example", docLine(`STRIPE_KEY = "` + vStripeDoc + `"`), "INFO", "WARN"},
	{"slack-sequential", docLine(`SLACK_TOKEN = "` + vSlackSeq + `"`), "INFO", "WARN"},
	{"google-xs", docLine(`MAPS_KEY = "` + vGoogleX + `"`), "INFO", "WARN"},
	{"database-url-changeme", docLine(`DATABASE_URL = "` + vDBChangeme + `"`), "INFO", "WARN"},
	{"npm-xs", docLine(`NPM_TOKEN = "` + vNPMXs + `"`), "INFO", "WARN"},
	{"api-key-sequential", docLine(`api_key = "1234567890abcdefghijklmnop"`), "INFO", "WARN"},
	{"password-hunter2", docLine(`password = "hunter2"`), "INFO", "WARN"},
	// The common-placeholder list: a well-known sample password, in any file.
	{"password-password123", docLine(`password = "password123"`), "INFO", "WARN"},
	{"password-passw0rd", docLine(`password = "Passw0rd"`), "INFO", "WARN"},
	{"password-administrator", docLine(`password = "administrator"`), "INFO", "WARN"},
}

// docScanStatuses writes content to path in a fresh tree, scans it with the
// real secrets scanner and runs the real finalization. It returns the strongest
// status reported for the file.
func docScanStatuses(t *testing.T, path, content string, deescalateTests bool) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	evid, err := secrets.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(evid) == 0 {
		return "none"
	}
	fs := finalize(evid, "HIGH", decision.Options{EnforceConfidence: true, DeescalateTests: deescalateTests})
	best := "none"
	for _, f := range fs {
		if statusRank(f.Status) > statusRank(best) {
			best = f.Status
		}
	}
	return best
}

var docContexts = []string{"README.md", "docs/guide.md", "docs/ref.rst", "docs/notes.txt", "docs/page.html", "CHANGELOG"}

func TestRC10b_CredentialsInDocumentation(t *testing.T) {
	for _, deesc := range []bool{false, true} {
		for _, ctx := range docContexts {
			for _, c := range docCreds {
				t.Run(fmt.Sprintf("deescalate=%v/%s/%s", deesc, ctx, c.name), func(t *testing.T) {
					if got := docScanStatuses(t, ctx, c.body(t), deesc); got != c.doc {
						t.Errorf("%s in %s is %s, want %s", c.name, ctx, got, c.doc)
					}
				})
			}
		}
	}
}

// Outside documentation the value is judged as before, except that a synthetic
// value is now recognised everywhere (the extended classifier and the
// common-placeholder list): WARN, never BLOCK, and never hidden.
func TestRC10b_TheSameCredentialsInSourceCode(t *testing.T) {
	for _, ctx := range []string{"src/config.py", "app.js"} {
		for _, c := range docCreds {
			t.Run(ctx+"/"+c.name, func(t *testing.T) {
				if got := docScanStatuses(t, ctx, c.body(t), false); got != c.src {
					t.Errorf("%s in %s is %s, want %s", c.name, ctx, got, c.src)
				}
			})
		}
	}
}

// Documentation is decided by the file, not by a directory name alone. A
// deployable config under docs/ (the jeecg Nacos configuration), a file named
// for what it holds, and a served page are not documentation: a real credential
// in them keeps its production weight.
func TestRC10b_NotEveryFileUnderDocsIsDocumentation(t *testing.T) {
	stripe := `STRIPE_KEY = "` + vStripe + `"` + "\n"
	cases := []struct{ path, content string }{
		{"docs/nacos/application.yaml", "spring:\n  datasource:\n    password: \"UYOo0f52uLnk#9!\"\n"},
		{"docs/nacos/config.properties", "db.password = \"UYOo0f52uLnk#9!\"\n"},
		{"docs/deploy/docker-compose.yml", `    password: "UYOo0f52uLnk#9!"` + "\n"},
		{"docs/examples/app.py", stripe},
		{"docs/examples/server.js", stripe},
		{"docs/setup.sh", stripe},
		{"docs/settings.json", `{ "stripe_key": "` + vStripe + `" }` + "\n"},
		{"docs/credentials.txt", stripe},
		{"credentials.txt", stripe},
		{"secrets.txt", stripe},
		{"public/index.html", stripe},
		{"static/page.html", stripe},
		{".env.example", "STRIPE_SECRET_KEY=" + vStripe + "\n"},
		// CL-1 / B-3: scripts and credential-named files at a documentation-looking
		// path. A shebang makes a file a script whatever it is called.
		{"bin/install", "#!/bin/sh\n" + stripe},
		{"scripts/setup", stripe},
		{"INSTALL", "#!/bin/sh\n" + stripe},
		{"tools/history", "#!/bin/sh\n" + stripe},
		{"docs/entrypoint", "#!/bin/sh\n" + stripe},
		{"docs/guide", "#!/usr/bin/env bash\n" + stripe},
		{"docs/aws/credentials", stripe},
		{"docs/secrets", stripe},
		{"docs/token", stripe},
		{"docs/kubeconfig", stripe},
		{"docs/kube/config", stripe},
		{"config/notes.txt", stripe},
		{"config/README.md", stripe},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := docScanStatuses(t, c.path, c.content, false); got != "BLOCK" {
				t.Errorf("%s is %s: it is not documentation, a real credential there must keep BLOCK", c.path, got)
			}
		})
	}
}

// Documentation and production code that share a title are never one finding
// (RC-9e): the sample in README.md does not carry the production key's BLOCK,
// and the production key does not take the sample's WARN.
func TestRC10b_DocumentationAndProductionDoNotShareAFinding(t *testing.T) {
	dir := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", `STRIPE_KEY = "`+vStripe+`"`+"\n")
	write("src/billing.py", `STRIPE_KEY = "`+vStripe+`"`+"\n")
	evid, err := secrets.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	fs := finalize(evid, "HIGH", decision.Options{EnforceConfidence: true})
	var got []string
	for _, f := range fs {
		for _, ep := range endpointsOfFinding(f) {
			got = append(got, ep+"="+f.Status)
		}
	}
	sort.Strings(got)
	want := "README.md:1=WARN src/billing.py:1=BLOCK"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

// A root INSTALL file with prose is documentation: the approved trade applies
// (WARN, unless the credential is provable offline).
func TestRC10b_ProseInstallFileIsDocumentation(t *testing.T) {
	prose := "Installing\n==========\n\nSet the key in your environment first:\n\n    STRIPE_KEY = \"" + vStripe + "\"\n"
	for _, p := range []string{"INSTALL", "docs/INSTALL", "NOTICE", "tools/history"} {
		if got := docScanStatuses(t, p, prose, false); got != "WARN" {
			t.Errorf("%s (prose) is %s, want WARN", p, got)
		}
	}
	// Provable offline: unchanged, still BLOCK.
	if got := docScanStatuses(t, "INSTALL", "Token:\n  export GITHUB_TOKEN="+vGHProvable+"\n", false); got != "BLOCK" {
		t.Errorf("a checksum-valid token in INSTALL is %s, want BLOCK", got)
	}
}
