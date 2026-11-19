package engine

// C1-1 (orchestrator correction, inside RC-9e): invariant (i), "no raising", for
// the flags only the producer knows.
//
// The occurrence class that keeps different own evidence in different findings
// was read from the finding alone. Placeholder, SyntheticValue, OfflineProvable
// and ProviderAnchored are not on models.Finding, so a fixture-shaped credential
// could share a finding with a real one and be reported at the real one's
// status: fe's `password: "password"` (a field-map entry) sat in a BLOCK finding
// with real-looking passwords of other files. The production grouping now reads
// the provenance index too, so an occurrence never shares a finding with one
// whose own evidence is stronger or weaker.
//
// These tests drive the REAL orchestrator finalization (finalizeOnce) and the
// real scanner, not a test copy of the pipeline.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

type pvOcc struct {
	kind        string // prod | test | doc
	n           int
	placeholder bool // Placeholder (any fixture signal, incl. the name)
	synthetic   bool // SyntheticValue (value evidence only)
	provable    bool // OfflineProvable (documentation only)
	anchored    bool // ProviderAnchored
}

func (o pvOcc) endpoint() string {
	switch o.kind {
	case "test":
		return fmt.Sprintf("tests/test_m%d.py:2", o.n)
	case "doc":
		return fmt.Sprintf("docs/m%d.md:2", o.n)
	}
	return fmt.Sprintf("src/m%d.py:2", o.n)
}

func (o pvOcc) ev() evidence.Evidence {
	ep := o.endpoint()
	line := ep
	return evidence.Evidence{
		ID: "SEC-HARDCODED_PASSWORD", RuleID: "secrets/HARDCODED_PASSWORD", Title: "Hardcoded password in source code",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets",
		Endpoint: ep, Line: &line, Evidence: "password=\"[REDACTED len=16]\"", Confidence: models.ConfidenceHigh,
		Secret:      &models.SecretRef{Identifier: "password", File: ep[:len(ep)-2]},
		Placeholder: o.placeholder, SyntheticValue: o.synthetic, OfflineProvable: o.provable, ProviderAnchored: o.anchored,
	}
}

func (o pvOcc) String() string {
	return fmt.Sprintf("%s[ph=%v syn=%v prv=%v anc=%v]", o.endpoint(), o.placeholder, o.synthetic, o.provable, o.anchored)
}

// pvStatuses finalizes the occurrences with the production pipeline and maps each
// occurrence's endpoint to the status of the finding it is reported under.
func pvStatuses(t *testing.T, occs []pvOcc) map[string]string {
	t.Helper()
	evs := make([]evidence.Evidence, len(occs))
	for i, o := range occs {
		evs[i] = o.ev()
	}
	fs, _ := finalizeOnce(t, evs, scanOpts{})
	return statusByEndpoint(fs)
}

// pvConfigs are the own-evidence shapes a password occurrence can have.
func pvConfigs(n int) []pvOcc {
	return []pvOcc{
		{kind: "prod", n: n},
		{kind: "prod", n: n, placeholder: true},                  // a FAKE_ name only
		{kind: "prod", n: n, placeholder: true, synthetic: true}, // a sample value ("password")
		{kind: "prod", n: n, placeholder: true, anchored: true},  // a provider-signed value with a fixture name
		{kind: "test", n: n},
		{kind: "test", n: n, placeholder: true, synthetic: true},
		{kind: "doc", n: n},                                     // real-format, not provable
		{kind: "doc", n: n, provable: true},                     // provable offline
		{kind: "doc", n: n, placeholder: true, synthetic: true}, // a sample in a README
		{kind: "doc", n: n, placeholder: true},                  // a FAKE_ name in a README
	}
}

// Every ordered pair of own-evidence shapes: neither occurrence's status depends
// on the other. This is invariant (i) and (ii) at once.
func TestC11_PairsOfOccurrencesKeepTheirOwnStatus(t *testing.T) {
	cfgs := pvConfigs(0)
	alone := map[int]string{}
	for i, c := range cfgs {
		c.n = 1
		alone[i] = pvStatuses(t, []pvOcc{c})[c.endpoint()]
	}
	for i := range cfgs {
		for j := range cfgs {
			a, b := cfgs[i], cfgs[j]
			a.n, b.n = 1, 2
			got := pvStatuses(t, []pvOcc{a, b})
			if got[a.endpoint()] != alone[i] {
				t.Errorf("%v is reported %s beside %v, but %s alone", a, got[a.endpoint()], b, alone[i])
			}
			if got[b.endpoint()] != alone[j] {
				t.Errorf("%v is reported %s beside %v, but %s alone", b, got[b.endpoint()], a, alone[j])
			}
		}
	}
}

// The property over random sets: the status of every occurrence in the set equals
// the status it gets alone, whatever the other files hold.
func TestC11_StatusIsIndependentOfPlaceholderAndSyntheticNeighbours(t *testing.T) {
	rng := rand.New(rand.NewSource(20261117))
	for n := 0; n < 250; n++ {
		size := 2 + rng.Intn(6)
		occs := make([]pvOcc, size)
		for i := range occs {
			c := pvConfigs(i + 1)[rng.Intn(10)]
			occs[i] = c
		}
		together := pvStatuses(t, occs)
		for _, o := range occs {
			alone := pvStatuses(t, []pvOcc{o})[o.endpoint()]
			if together[o.endpoint()] != alone {
				var all []string
				for _, x := range occs {
					all = append(all, x.String())
				}
				sort.Strings(all)
				t.Fatalf("set %d: %v is reported %s in the set but %s alone (%s)\nset: %v", n, o, together[o.endpoint()], alone,
					map[bool]string{true: "raised", false: "hidden"}[statusRank(together[o.endpoint()]) > statusRank(alone)], all)
			}
		}
	}
}

// fe: a form's field map (`password: "password"`) next to real-looking
// passwords in other files of the same kind of path. The field-map entry is a
// sample (the common-placeholder list) and is a WARN of its own; the real-looking
// passwords stay a BLOCK of their own. Neither takes the other's status.
func TestC11_FieldMapPasswordDoesNotShareAFindingWithRealPasswords(t *testing.T) {
	root := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app/signup/page.tsx", "const fields = {\n  name: \"name\", email: \"email\", password: \"password\",\n};\n")
	write("lib/auth/defaults.ts", "export const DEFAULT_PASSWORD = \"E2epass!234\";\n")
	write("lib/auth/login.ts", "export const go = (email: string) => login(email, { password: \"wrong-pass-92xK\" });\n")
	code, rep := codeScan(t, root, scanOpts{})
	got := map[string]string{}
	for _, f := range passwordFindings(rep) {
		for _, ep := range endpointsOfFinding(f) {
			got[ep] = f.Status
		}
	}
	if got["app/signup/page.tsx:2"] != "WARN" {
		t.Errorf("the field-map password is %q, want WARN (a sample, judged on its own evidence): %v", got["app/signup/page.tsx:2"], got)
	}
	for _, ep := range []string{"lib/auth/defaults.ts:1", "lib/auth/login.ts:1"} {
		if got[ep] != "BLOCK" {
			t.Errorf("%s is %q, want BLOCK: a real-looking password must not be lowered by a sample's finding: %v", ep, got[ep], got)
		}
	}
	if code != 1 {
		t.Errorf("exit = %d: the real-looking passwords must still gate the build", code)
	}
}

// A hybrid (--url + --code) scan runs the evidence through the correlator, which
// rebuilds every Evidence from a Finding and restores the producer-set flags from
// an allow-list. SyntheticValue and OfflineProvable are producer-set (the
// scanner knows the value), with no endpoint-derived fallback: dropped there, the
// documentation rules would work on a code-only scan and be dead on a hybrid one.
func TestC11_DocumentationFlagsSurviveTheHybridPipeline(t *testing.T) {
	doc := func(file, title string) evidence.Evidence {
		ep := file + ":2"
		line := ep
		return evidence.Evidence{
			ID: "SEC-X", Title: title, Category: "secrets", Endpoint: ep, Line: &line,
			Severity: models.SeverityCritical, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
			Evidence: "token=\"[REDACTED len=40]\"", Fix: "f",
		}
	}
	synthetic := doc("docs/a.md", "sample token")
	synthetic.Placeholder, synthetic.SyntheticValue = true, true
	provable := doc("docs/b.md", "provable token")
	provable.OfflineProvable = true
	unprovable := doc("docs/c.md", "real-format token")
	probe := evidence.Evidence{
		Title: "Missing security header: Content-Security-Policy", Category: "headers", Endpoint: "https://example.test/",
		Severity: models.SeverityMedium, Source: models.SourceBlackbox,
	}
	evid := []evidence.Evidence{synthetic, provable, unprovable, probe}
	if !hasWhitebox(evidence.ToFindings(evid)) || !hasBlackbox(evidence.ToFindings(evid)) {
		t.Fatal("test premise broken: not a hybrid scan, so correlation would be skipped")
	}
	evid = CorrelateEvidence(evid)
	out := finalizeIndexed(evid, evidence.NewProvenanceIndex(evid), "HIGH", isoOpts(false))
	got := statusByEndpoint(out)
	want := map[string]string{"docs/a.md:2": "INFO", "docs/b.md:2": "BLOCK", "docs/c.md:2": "WARN"}
	for ep, w := range want {
		if got[ep] != w {
			t.Errorf("%s is %q after correlation, want %q: a producer-set flag was lost in CorrelateEvidence", ep, got[ep], w)
		}
	}
}
