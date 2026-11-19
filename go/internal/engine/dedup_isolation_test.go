package engine

// RC-9e (Round 6 closure, owner ruling OR-85): cross-file deduplication
// isolation.
//
// Deduplicate groups findings that share (Severity, Category, Title) across
// files and used to give the group the MAXIMUM confidence and the OR of the
// proof of every member, and the "agree or drop" InTest of the whole set. So
// one file's evidence set the status of every occurrence in every other file:
// a require() that no analyzer graded above MEDIUM BLOCKed because one other
// file's finding of the same title was HIGH, 708 test-file passwords of one
// healthchecks group BLOCKed because 5 production ones did.
//
// The ruling: the evidence of an occurrence in one file must not raise the
// status of an occurrence in another file, and (the invariant that matters
// more) an occurrence whose own evidence BLOCKs must never sit under a finding
// that does not. Occurrences with different own evidence therefore never share
// a finding. These tests pin both halves and then check them as a property:
// for any set of whitebox occurrences, the status each occurrence is reported
// under equals the status it gets alone.

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

type isoOcc struct {
	title    string
	endpoint string
	conf     models.Confidence
	tier     models.SourceTier
	chain    bool // a proven taint path to the sink
}

func (o isoOcc) ev() evidence.Evidence {
	e := evidence.Evidence{
		// CRITICAL, the ceiling escalateNonCorrelatedReachable saturates at: an
		// occurrence with a proven path would otherwise be escalated out of its
		// neighbours' severity, and into a group of its own, before grouping.
		Title: o.title, Category: "injection", Endpoint: o.endpoint, Severity: models.SeverityCritical,
		Source: models.SourceWhitebox, SourceTier: o.tier, Confidence: o.conf,
		Evidence: "e:" + o.endpoint, Fix: "f:" + o.title,
		References: []string{"CWE-95"},
	}
	if o.chain {
		e.Reachable = true
		e.TaintChain = []models.TaintLink{{File: o.endpoint, Line: 1, Expr: "req.query.q"}, {File: o.endpoint, Line: 2, Expr: "sink(q)"}}
	}
	return e
}

// isoOpts are the production defaults (--enforce-confidence on), with the
// test-fixture de-escalation as asked.
func isoOpts(deescalate bool) decision.Options {
	return decision.Options{EnforceConfidence: true, DeescalateTests: deescalate}
}

func isoFinalize(occs []isoOcc, opts decision.Options) []models.Finding {
	evid := make([]evidence.Evidence, len(occs))
	for i, o := range occs {
		evid[i] = o.ev()
	}
	return finalize(evid, "HIGH", opts)
}

// statusByEndpoint maps every occurrence endpoint to the status of the finding
// it is reported under.
func statusByEndpoint(fs []models.Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		eps := f.AffectedEndpoints
		if len(eps) == 0 {
			eps = []string{f.Endpoint}
		}
		for _, ep := range eps {
			out[ep] = f.Status
		}
	}
	return out
}

func endpointsOfFinding(f models.Finding) []string {
	if len(f.AffectedEndpoints) > 0 {
		return append([]string(nil), f.AffectedEndpoints...)
	}
	return []string{f.Endpoint}
}

const requireTitle = "require() called with a non-literal path"

// ace.js:4521 is a require() that nothing graded above MEDIUM. require.min.js:5
// carries a HIGH grade (a same-construct partner asserted it). They share a
// title, so one finding took the HIGH for both, and ace.js BLOCKed.
func TestDedupIsolation_OneFilesConfidenceDoesNotRaiseAnotherFile(t *testing.T) {
	got := isoFinalize([]isoOcc{
		{title: requireTitle, endpoint: "static/js/libs/ace.js:4521", conf: models.ConfidenceMedium, tier: models.TierNativeGo},
		{title: requireTitle, endpoint: "static/js/libs/require.min.js:5", conf: models.ConfidenceHigh, tier: models.TierNativeGo},
	}, isoOpts(false))
	st := statusByEndpoint(got)
	if st["static/js/libs/ace.js:4521"] != "WARN" {
		t.Errorf("ace.js:4521 is reported %s: another file's HIGH raised it (it earns WARN)", st["static/js/libs/ace.js:4521"])
	}
	if st["static/js/libs/require.min.js:5"] != "BLOCK" {
		t.Errorf("require.min.js:5 is reported %s: its own HIGH evidence earns BLOCK", st["static/js/libs/require.min.js:5"])
	}
	if len(got) != 2 {
		t.Errorf("want one finding per own-evidence class, got %d", len(got))
	}
}

// A proven taint path is the proof of ITS occurrence.
func TestDedupIsolation_OneFilesProofDoesNotReachAnotherFile(t *testing.T) {
	const title = "SQL query built via string formatting"
	got := isoFinalize([]isoOcc{
		{title: title, endpoint: "app/a.py:10", conf: models.ConfidenceMedium, tier: models.TierTreeSitter, chain: true},
		{title: title, endpoint: "app/b.py:20", conf: models.ConfidenceMedium, tier: models.TierTreeSitter},
	}, isoOpts(false))
	for _, f := range got {
		eps := endpointsOfFinding(f)
		hasB := false
		for _, ep := range eps {
			hasB = hasB || ep == "app/b.py:20"
		}
		if hasB && (f.Reachable || len(f.TaintChain) > 0) {
			t.Errorf("b.py:20 is reported under a finding that carries a.py's proof (reachable=%v chain=%d, endpoints %v)", f.Reachable, len(f.TaintChain), eps)
		}
	}
	st := statusByEndpoint(got)
	if st["app/b.py:20"] == "BLOCK" {
		t.Errorf("b.py:20 has no proof of its own and must not BLOCK on a.py's")
	}
}

// healthchecks: one production occurrence and hundreds in tests. The test
// occurrences earn a WARN (test code carries no deterministic-detection
// weight); they must not be raised to the production occurrence's BLOCK, and
// the production occurrence must not be lowered by them.
func TestDedupIsolation_TestFilesDoNotShareAFindingWithProduction(t *testing.T) {
	const title = "Hardcoded password in source code"
	occs := []isoOcc{{title: title, endpoint: "hc/settings.py:7", conf: models.ConfidenceHigh}}
	for i := 0; i < 5; i++ {
		occs = append(occs, isoOcc{title: title, endpoint: fmt.Sprintf("hc/tests/test_api_%d.py:%d", i, 10+i), conf: models.ConfidenceHigh})
	}
	got := isoFinalize(occs, isoOpts(false))
	st := statusByEndpoint(got)
	if st["hc/settings.py:7"] != "BLOCK" {
		t.Errorf("the production credential is reported %s, want BLOCK", st["hc/settings.py:7"])
	}
	for i := 0; i < 5; i++ {
		ep := fmt.Sprintf("hc/tests/test_api_%d.py:%d", i, 10+i)
		if st[ep] == "BLOCK" {
			t.Errorf("%s is reported BLOCK only because a production occurrence shares its finding", ep)
		}
	}
}

// The purpose of the grouping is intact: occurrences with the same own
// evidence in many files are still ONE finding with every endpoint.
func TestDedupIsolation_SameEvidenceStillGroupsAcrossFiles(t *testing.T) {
	var occs []isoOcc
	for i := 0; i < 7; i++ {
		occs = append(occs, isoOcc{title: requireTitle, endpoint: fmt.Sprintf("src/m%d.js:%d", i, i+1), conf: models.ConfidenceMedium, tier: models.TierNativeGo})
	}
	got := isoFinalize(occs, isoOpts(false))
	if len(got) != 1 || len(got[0].AffectedEndpoints) != 7 {
		t.Fatalf("seven occurrences with the same evidence must be one finding with seven endpoints, got %d findings", len(got))
	}
}

// Blackbox findings are not a file's evidence: one header check across 21
// endpoints stays one finding.
func TestDedupIsolation_BlackboxGroupingIsUntouched(t *testing.T) {
	var fs []models.Finding
	for i := 0; i < 21; i++ {
		fs = append(fs, models.Finding{Title: "Missing Content-Security-Policy header", Category: "headers", Severity: models.SeverityMedium,
			Source: models.SourceBlackbox, Endpoint: fmt.Sprintf("GET /p%d", i), Confidence: models.ConfidenceHigh})
	}
	if got := Deduplicate(fs); len(got) != 1 || len(got[0].AffectedEndpoints) != 21 {
		t.Fatalf("blackbox grouping changed: %d findings", len(got))
	}
}

// TestDedupIsolation_StatusIsIndependentOfTheOtherOccurrences is the invariant
// as a property. For many random sets of whitebox occurrences (two titles,
// production and test files, three grades, four tiers, with and without a
// proven path), the status each occurrence is reported under in the set equals
// the status it gets alone:
//
//	(i)  no raising: nobody is reported under a status its own evidence does not earn;
//	(ii) no hiding:  nobody whose own evidence BLOCKs sits under a non-BLOCK finding.
//
// Checked with the test-fixture de-escalation on and off.
func TestDedupIsolation_StatusIsIndependentOfTheOtherOccurrences(t *testing.T) {
	rng := rand.New(rand.NewSource(20261116))
	titles := []string{requireTitle, "eval() with non-literal argument"}
	confs := []models.Confidence{models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow}
	tiers := []models.SourceTier{"", models.TierNativeGo, models.TierTreeSitter, models.TierSemgrepShim}
	for _, opts := range []decision.Options{isoOpts(false), isoOpts(true)} {
		for n := 0; n < 300; n++ {
			size := 2 + rng.Intn(6)
			occs := make([]isoOcc, size)
			for i := range occs {
				dir := "src"
				if rng.Intn(3) == 0 {
					dir = "tests"
				}
				occs[i] = isoOcc{
					title:    titles[rng.Intn(len(titles))],
					endpoint: fmt.Sprintf("%s/f%d_%d.js:%d", dir, n, i, 1+rng.Intn(50)),
					conf:     confs[rng.Intn(len(confs))],
					tier:     tiers[rng.Intn(len(tiers))],
					chain:    rng.Intn(5) == 0,
				}
			}
			together := statusByEndpoint(isoFinalize(occs, opts))
			for _, o := range occs {
				alone := statusByEndpoint(isoFinalize([]isoOcc{o}, opts))[o.endpoint]
				if together[o.endpoint] != alone {
					var all []string
					for _, x := range occs {
						all = append(all, fmt.Sprintf("%s[%s %s chain=%v] %s", x.endpoint, x.conf, x.tier, x.chain, x.title))
					}
					sort.Strings(all)
					t.Fatalf("deescalate=%v set %d: %s is reported %s in the set but %s alone (%s)\nset: %v",
						opts.DeescalateTests, n, o.endpoint, together[o.endpoint], alone,
						map[bool]string{true: "raised", false: "hidden"}[statusRank(together[o.endpoint]) > statusRank(alone)], all)
				}
			}
		}
	}
}

func statusRank(s string) int {
	switch s {
	case "BLOCK":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

// The grouping outcome is a function of the SET of occurrences, not of their
// order (F-L6).
func TestDedupIsolation_OutcomeIsOrderIndependent(t *testing.T) {
	base := []isoOcc{
		{title: requireTitle, endpoint: "a/x.js:1", conf: models.ConfidenceMedium, tier: models.TierNativeGo},
		{title: requireTitle, endpoint: "b/y.js:2", conf: models.ConfidenceHigh, tier: models.TierNativeGo},
		{title: requireTitle, endpoint: "tests/z.js:3", conf: models.ConfidenceHigh, tier: models.TierNativeGo},
		{title: requireTitle, endpoint: "c/w.js:4", conf: models.ConfidenceMedium, tier: models.TierNativeGo},
	}
	render := func(fs []models.Finding) string {
		var rows []string
		for _, f := range fs {
			rows = append(rows, fmt.Sprintf("%s|%s|%v|%s|%s", f.Status, f.Confidence, endpointsOfFinding(f), f.Endpoint, f.ID))
		}
		sort.Strings(rows)
		return fmt.Sprint(rows)
	}
	want := ""
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 24; i++ {
		p := append([]isoOcc(nil), base...)
		rng.Shuffle(len(p), func(a, b int) { p[a], p[b] = p[b], p[a] })
		got := render(isoFinalize(p, isoOpts(false)))
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("order %d changed the grouping:\n got  %s\n want %s", i, got, want)
		}
	}
}

// A flag only the producer knows (Placeholder: the value is fixture-shaped) is
// not visible on the finding. The production grouping reads it from the
// provenance index (ProvenanceIndex.OccurrenceClass, C1-1), so a fixture-shaped
// occurrence is a finding of its own, and the second invariant holds a fortiori:
// a credential whose own evidence BLOCKs is never reported under a non-BLOCK
// finding because a fixture-shaped neighbour shares its title. (The full
// statement of both invariants for these flags is dedup_isolation_provenance_test.go.)
func TestDedupIsolation_AFixtureShapedNeighbourCannotHideABlock(t *testing.T) {
	mk := func(endpoint string, placeholder bool) evidence.Evidence {
		return evidence.Evidence{
			Title: "Hardcoded password in source code", Category: "secrets", Endpoint: endpoint,
			Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
			Evidence: "e:" + endpoint, Fix: "f", Placeholder: placeholder,
		}
	}
	real, fake := mk("app/settings.py:3", false), mk("app/example_settings.py:9", true)
	opts := isoOpts(false)
	alone := statusByEndpoint(finalize([]evidence.Evidence{real}, "HIGH", opts))["app/settings.py:3"]
	if alone != "BLOCK" {
		t.Fatalf("control: the real credential alone is %s, want BLOCK", alone)
	}
	for _, in := range [][]evidence.Evidence{{real, fake}, {fake, real}} {
		if got := statusByEndpoint(finalize(in, "HIGH", opts))["app/settings.py:3"]; got != "BLOCK" {
			t.Errorf("the real credential is reported %s beside a fixture-shaped one: a BLOCK was hidden", got)
		}
	}
}
