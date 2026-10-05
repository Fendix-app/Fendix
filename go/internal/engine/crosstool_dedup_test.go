package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// These tests lock the two dedup-boundary invariants of cross-tool
// corroboration:
//
//	Deduplication can never MANUFACTURE cross-tool corroboration.
//	Deduplication can never ERASE a validly established strong
//	corroboration merely because another duplicate occurrence of the same
//	logical vulnerability was not individually stamped.
//
// The division of labour is absolute: CorrelateCrossTool is the ONLY
// producer of corroboration (it establishes trust, backed by a tool-identity
// record); every later stage — dedup, the provenance index, restore — may
// only preserve or conservatively discard that record, never invent it.

// runFinalizationSlice mirrors the exact finalize/stampDecisions sequence the
// orchestrator runs between cross-tool correlation and the decision layer:
// correlate → index → project → dedup → restore. Returning the restored
// Evidence the decision layer would actually see keeps these tests honest —
// they exercise the REAL pipeline path, not a convenient shortcut.
func runFinalizationSlice(evs []evidence.Evidence) []evidence.Evidence {
	evid, _ := CorrelateCrossTool(evs)
	prov := evidence.NewProvenanceIndex(evid)
	findings := evidence.ToFindings(evid)
	findings = CollapseDuplicateLocations(findings)
	findings = Deduplicate(findings)
	return prov.Restore(evidence.FromFindings(findings))
}

// TestCorroborationSurvivesUncorroboratedDuplicate is the risky scenario from
// the hardening review: native A is strongly corroborated by imported B, and
// native A' is a dedup-equivalent duplicate occurrence (same Title, Category,
// Severity — a different endpoint) that was, correctly, never stamped. Before
// the proof-union fold, the group merge computed corroborated AND
// uncorroborated = false and silently erased the CodeQL confirmation.
func TestCorroborationSurvivesUncorroboratedDuplicate(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/admin.py:50", "50") // same Title/Category/Severity → same dedup group
	b := importedSQLi("codeql", "app/views.py:102", "102")

	restored := runFinalizationSlice([]evidence.Evidence{a, aPrime, b})
	if len(restored) != 1 {
		t.Fatalf("want one representative finding (B collapsed into A, A' deduped), got %d", len(restored))
	}
	rep := restored[0]
	if rep.Source != models.SourceWhitebox {
		t.Fatalf("representative must be native fendix, got %q", rep.Source)
	}
	if !rep.CrossToolCorroborated {
		t.Fatal("the uncorroborated duplicate A' must NOT erase the valid A↔CodeQL confirmation")
	}
	if len(rep.CorroboratingTools) != 1 || rep.CorroboratingTools[0] != "codeql" {
		t.Fatalf("CorroboratingTools = %v, want [codeql]", rep.CorroboratingTools)
	}

	// And the surviving proof must still feed the corroboration arm.
	d := decision.DecideWithOptions(rep, "HIGH", decision.Options{EnforceConfidence: true})
	if d.Status != decision.StatusBlock {
		t.Fatalf("the corroborated representative must BLOCK at --fail-on HIGH, got %v (%s)", d.Status, d.Reason)
	}
	if !strings.Contains(d.Reason, "independent cross-tool corroboration") {
		t.Fatalf("BLOCK must be attributed to the cross-tool signal, got %q", d.Reason)
	}
}

// TestCorroborationSurvivesIdentityCollision covers the second erasure path:
// a duplicate occurrence sharing A's EXACT (Category, Endpoint, Title)
// identity — a second analyzer emitting the same claim at the same location,
// but without a CWE reference token, so it can never classify strongly
// against B on its own. The two entries collide in NewProvenanceIndex and
// are merged there; the merge must preserve A's proof.
func TestCorroborationSurvivesIdentityCollision(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/views.py:100", "100")
	aPrime.References = nil // no CWE token → no weakness → never strong vs B
	aPrime.SourceTier = models.TierNativeGo
	b := importedSQLi("codeql", "app/views.py:102", "102")

	restored := runFinalizationSlice([]evidence.Evidence{a, aPrime, b})
	if len(restored) != 1 {
		t.Fatalf("want one representative, got %d", len(restored))
	}
	if !restored[0].CrossToolCorroborated {
		t.Fatal("an identity-colliding unstamped duplicate must not erase the established proof")
	}
	if len(restored[0].CorroboratingTools) != 1 || restored[0].CorroboratingTools[0] != "codeql" {
		t.Fatalf("CorroboratingTools = %v, want [codeql]", restored[0].CorroboratingTools)
	}
}

// TestDedupCannotManufactureCorroboration is the inverse guarantee: when NO
// strong record was ever established (B is 300 lines away), grouping
// dedup-equivalent occurrences must not conjure one — no flag, no tools, no
// cross-tool BLOCK.
func TestDedupCannotManufactureCorroboration(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/admin.py:50", "50")
	b := importedSQLi("codeql", "app/views.py:400", "400") // same CWE, same file, far away

	restored := runFinalizationSlice([]evidence.Evidence{a, aPrime, b})
	if len(restored) != 2 {
		t.Fatalf("want the native group + the (non-collapsed) import, got %d rows", len(restored))
	}
	for _, ev := range restored {
		if ev.CrossToolCorroborated || len(ev.CorroboratingTools) > 0 {
			t.Fatalf("no strong record exists, so nothing may carry corroboration: %+v", ev.CorroboratingTools)
		}
		d := decision.DecideWithOptions(ev, "HIGH", decision.Options{EnforceConfidence: true})
		if d.Status == decision.StatusBlock {
			t.Fatalf("nothing here is corroborated — BLOCK is manufactured trust (%s)", d.Reason)
		}
		if strings.Contains(d.Reason, "cross-tool") {
			t.Fatalf("the cross-tool signal must be absent, got %q", d.Reason)
		}
	}
}

// TestMultipleCorroboratingTools: fendix native confirmed by BOTH CodeQL and
// Semgrep, with a duplicate CodeQL result thrown in. The provenance must list
// each independent external tool exactly once, deterministically sorted —
// never ["codeql", "codeql"] — and duplicate same-tool evidence must not
// inflate anything.
func TestMultipleCorroboratingTools(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	b1 := importedSQLi("codeql", "app/views.py:102", "102")
	b1dup := importedSQLi("codeql", "app/views.py:103", "103")
	b2 := importedSQLi("semgrep", "app/views.py:101", "101")

	restored := runFinalizationSlice([]evidence.Evidence{a, b1, b1dup, b2})
	if len(restored) != 1 {
		t.Fatalf("all imports strongly match the native and collapse into it, got %d rows", len(restored))
	}
	rep := restored[0]
	if rep.Source != models.SourceWhitebox {
		t.Fatalf("representative must stay native, got %q", rep.Source)
	}
	got := strings.Join(rep.CorroboratingTools, ",")
	if got != "codeql,semgrep" {
		t.Fatalf("CorroboratingTools = %q, want exactly \"codeql,semgrep\" (sorted, deduped)", got)
	}
}

// ── The public contract ─────────────────────────────────────────────────────

// TestPublicCorroborationSurvivesUncorroboratedDuplicate is the reason the
// public fields are stamped in stampDecisions from the RESTORED evidence
// rather than projected through evidence.ToFinding. Projecting would publish
// whichever duplicate won findingLess in dedup — reintroducing exactly the
// erasure the proof-union fold fixed, but on a public surface this time.
func TestPublicCorroborationSurvivesUncorroboratedDuplicate(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/admin.py:50", "50") // dedup-equivalent, never stamped
	b := importedSQLi("codeql", "app/views.py:102", "102")

	evid, _ := CorrelateCrossTool([]evidence.Evidence{a, aPrime, b})
	prov := evidence.NewProvenanceIndex(evid)
	findings := evidence.ToFindings(evid)
	findings = Deduplicate(findings)
	stampDecisions(findings, prov, "HIGH", decision.Options{EnforceConfidence: true})

	if len(findings) != 1 {
		t.Fatalf("want one representative, got %d", len(findings))
	}
	if !findings[0].CrossToolCorroborated {
		t.Fatal("the PUBLIC field must survive an uncorroborated dedup duplicate")
	}
	if strings.Join(findings[0].CorroboratingTools, ",") != "codeql" {
		t.Fatalf("public tools = %v, want [codeql]", findings[0].CorroboratingTools)
	}
}

// TestUncorroboratedFindingOmitsPublicFields keeps existing reports
// byte-identical: both fields are omitempty and must not appear.
func TestUncorroboratedFindingOmitsPublicFields(t *testing.T) {
	f := nativeSQLi("app/views.py:100", "100").ToFinding()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "cross_tool_corroborated") ||
		strings.Contains(string(raw), "corroborating_tools") {
		t.Fatalf("uncorroborated findings must omit both keys: %s", raw)
	}
}

// ── Exact-CWE conservatism (deliberate v1 trust boundary) ───────────────────
//
// Strong corroboration requires an EXACT normalized CWE intersection. CWE
// parent/child relationships, taxonomy traversal, and category equivalence
// are intentionally not resolved: a false non-correlation is preferable to a
// false independent-engine confirmation.

func TestExactCWE_IntersectionAcrossMultiWeaknessSets(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	a.References = []string{"CWE-89", "CWE-20"}
	b := importedSQLi("codeql", "app/views.py:102", "102")
	b.Weakness = []string{"CWE-79", "CWE-89"}

	if got := ClassifyCrossTool(a, b); got != MatchStrong {
		t.Fatalf("sets intersect on CWE-89 → strong, got %v", got)
	}
}

func TestExactCWE_RelatedButNonIdenticalNeverStrong(t *testing.T) {
	// CWE-564 (SQL Injection: Hibernate) is a taxonomic child of CWE-89.
	// The relationship is real — and deliberately NOT resolved.
	a := nativeSQLi("app/views.py:100", "100") // CWE-89
	b := importedSQLi("codeql", "app/views.py:102", "102")
	b.Weakness = []string{"CWE-564"}

	if got := ClassifyCrossTool(a, b); got == MatchStrong {
		t.Fatal("taxonomically related CWEs must NOT satisfy the exact-intersection requirement")
	}
}

func TestExactCWE_MissingWeaknessOnEitherSideNeverStrong(t *testing.T) {
	// Import carries CWE-89, the native side has no CWE token at all: the
	// missing weakness must not be inferred from title/category/references.
	a := nativeSQLi("app/views.py:100", "100")
	a.References = []string{"https://owasp.org/sqli"} // no exact CWE token
	b := importedSQLi("codeql", "app/views.py:102", "102")

	if got := ClassifyCrossTool(a, b); got == MatchStrong {
		t.Fatal("a side with no recognizable weakness must never corroborate strongly")
	}
}
