package evidence

import (
	"reflect"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func probeEvidence(endpoint string) Evidence {
	return Evidence{
		Title:           "Missing Content-Security-Policy header",
		Category:        "headers",
		Endpoint:        endpoint,
		Severity:        models.SeverityMedium,
		Source:          models.SourceBlackbox,
		Payload:         "GET " + endpoint,
		Response:        "HTTP/1.1 401 Unauthorized",
		ResponseContext: "4xx",
		Lineage:         []Evidence{{Source: models.SourceBlackbox, Category: "headers"}},
	}
}

// TestRestoreRoundTripsInternalProvenance is the core contract: whatever
// ToFinding drops, the index puts back.
func TestRestoreRoundTripsInternalProvenance(t *testing.T) {
	in := []Evidence{probeEvidence("GET /admin")}
	ix := NewProvenanceIndex(in)

	projected := FromFindings(ToFindings(in))
	if projected[0].ResponseContext != "" || projected[0].Payload != "" || len(projected[0].Lineage) != 0 {
		t.Fatal("guard: the projection is supposed to be lossy here")
	}

	got := ix.Restore(projected)
	if got[0].Payload != in[0].Payload {
		t.Errorf("Payload = %q, want %q", got[0].Payload, in[0].Payload)
	}
	if got[0].Response != in[0].Response {
		t.Errorf("Response = %q, want %q", got[0].Response, in[0].Response)
	}
	if got[0].ResponseContext != in[0].ResponseContext {
		t.Errorf("ResponseContext = %q, want %q", got[0].ResponseContext, in[0].ResponseContext)
	}
	if !reflect.DeepEqual(got[0].Lineage, in[0].Lineage) {
		t.Errorf("Lineage = %+v, want %+v", got[0].Lineage, in[0].Lineage)
	}
}

// TestRestoreDoesNotMutateInput — Restore returns a copy; the caller's slice
// is untouched.
func TestRestoreDoesNotMutateInput(t *testing.T) {
	in := []Evidence{probeEvidence("GET /admin")}
	ix := NewProvenanceIndex(in)
	projected := FromFindings(ToFindings(in))

	_ = ix.Restore(projected)
	if projected[0].ResponseContext != "" {
		t.Errorf("Restore mutated its input: ResponseContext = %q", projected[0].ResponseContext)
	}
}

// TestRestoreNeverOverwrites — provenance already present on the input wins,
// so restoring Evidence that never lost anything is a no-op.
func TestRestoreNeverOverwrites(t *testing.T) {
	indexed := probeEvidence("GET /admin")
	ix := NewProvenanceIndex([]Evidence{indexed})

	live := probeEvidence("GET /admin")
	live.ResponseContext = "static-asset"
	live.Payload = "already here"

	got := ix.Restore([]Evidence{live})
	if got[0].ResponseContext != "static-asset" || got[0].Payload != "already here" {
		t.Errorf("Restore overwrote live provenance: %+v", got[0])
	}
}

// TestRestoreUnknownIdentityIsANoOp — a miss degrades to "score the projected
// fields only"; it must never invent provenance from a different finding.
func TestRestoreUnknownIdentityIsANoOp(t *testing.T) {
	ix := NewProvenanceIndex([]Evidence{probeEvidence("GET /admin")})

	other := Evidence{Title: "Different finding", Category: "cors", Endpoint: "GET /admin"}
	got := ix.Restore([]Evidence{other})
	if !reflect.DeepEqual(got[0], other) {
		t.Errorf("unknown identity picked up provenance: %+v", got[0])
	}
}

// TestIdentityCollisionMergesConservatively — two Evidence sharing an identity
// but disagreeing on a field collapse that field to zero, so a bonus is only
// awarded when every occurrence earned it.
func TestIdentityCollisionMergesConservatively(t *testing.T) {
	a := probeEvidence("GET /admin")
	b := probeEvidence("GET /admin")
	b.ResponseContext = ""
	b.Payload = "a different probe"

	ix := NewProvenanceIndex([]Evidence{a, b})
	got := ix.Restore(FromFindings(ToFindings([]Evidence{a})))
	if got[0].ResponseContext != "" {
		t.Errorf("disagreeing ResponseContext should collapse to \"\", got %q", got[0].ResponseContext)
	}
	if got[0].Payload != "" {
		t.Errorf("disagreeing Payload should collapse to \"\", got %q", got[0].Payload)
	}
	if got[0].Response != a.Response {
		t.Errorf("agreeing Response should survive, got %q", got[0].Response)
	}
}

// TestIndexIsOrderIndependent — the merge is a commutative/associative meet,
// so a re-ordered input (worker-pool interleaving) yields the same index.
// Same F-L6 determinism property dedup enforces.
func TestIndexIsOrderIndependent(t *testing.T) {
	a := probeEvidence("GET /admin")
	b := probeEvidence("GET /admin")
	b.ResponseContext = ""
	c := probeEvidence("GET /admin")
	c.Payload = "third"

	fwd := NewProvenanceIndex([]Evidence{a, b, c})
	rev := NewProvenanceIndex([]Evidence{c, b, a})
	mid := NewProvenanceIndex([]Evidence{b, a, c})
	if !reflect.DeepEqual(fwd, rev) || !reflect.DeepEqual(fwd, mid) {
		t.Errorf("index depends on input order:\n fwd=%+v\n rev=%+v\n mid=%+v", fwd, rev, mid)
	}
}

// TestDedupGroupMergesAcrossAffectedEndpoints — a finding that dedup collapsed
// takes the merge over its whole group, so a de-escalation tag survives only
// when every endpoint carried it.
func TestDedupGroupMergesAcrossAffectedEndpoints(t *testing.T) {
	admin := probeEvidence("GET /admin")
	public := probeEvidence("GET /public")
	public.ResponseContext = ""

	ix := NewProvenanceIndex([]Evidence{admin, public})

	// What Deduplicate produces: the primary plus the group's endpoints.
	merged := FromFinding(admin.ToFinding())
	merged.AffectedEndpoints = []string{"GET /admin", "GET /public"}

	got := ix.Restore([]Evidence{merged})
	if got[0].ResponseContext != "" {
		t.Errorf("group with a non-4xx member kept the tag: %q", got[0].ResponseContext)
	}

	// All members tagged → the tag survives.
	public.ResponseContext = "4xx"
	ix = NewProvenanceIndex([]Evidence{admin, public})
	got = ix.Restore([]Evidence{merged})
	if got[0].ResponseContext != "4xx" {
		t.Errorf("group where every member was 4xx lost the tag: %q", got[0].ResponseContext)
	}
}

// TestIdentityKeyIsInjective — the NUL-separated encoding must not let two
// different identities collide (e.g. "a|b" + "c" vs "a" + "b|c").
func TestIdentityKeyIsInjective(t *testing.T) {
	if identityKey("a", "b", "c") == identityKey("ab", "", "c") {
		t.Error("identityKey collides across a field boundary")
	}
	if identityKey("a", "b", "c") != identityKey("a", "b", "c") {
		t.Error("identityKey is not stable")
	}
}

// TestProvenanceIndexNilAndEmpty — nil-safe on both sides.
func TestProvenanceIndexNilAndEmpty(t *testing.T) {
	if got := NewProvenanceIndex(nil); len(got) != 0 {
		t.Errorf("NewProvenanceIndex(nil) = %v, want empty", got)
	}
	if got := ProvenanceIndex(nil).Restore(nil); got != nil {
		t.Errorf("nil.Restore(nil) = %v, want nil", got)
	}
	in := []Evidence{probeEvidence("GET /admin")}
	if got := ProvenanceIndex(nil).Restore(in); !reflect.DeepEqual(got, in) {
		t.Errorf("nil index should pass evidence through unchanged")
	}
}

// TestInternalProvenanceRoundTripsAndMergesConservatively covers the three
// producer-set flags that joined InTest: DirectObservation, Placeholder and
// UnconfirmedByLiveScan.
//
// They are grouped into ONE table because they share the exact property that
// makes them dangerous: none of them can be re-derived from the endpoint the
// way NewProvenanceIndex re-derives InTest via models.IsTestPath. A dropped hop
// is therefore permanent and silent — the flag simply reads false forever, and
// the rule that depends on it looks like it was never written. Each flag has to
// clear all three bars: it must survive the lossy projection, it must merge
// with "agree or drop" so one member of a dedup group cannot speak for the
// rest, and the fold must not depend on input order (F-L6).
func TestInternalProvenanceRoundTripsAndMergesConservatively(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Evidence, bool)
		get  func(Evidence) bool
	}{
		{
			name: "DirectObservation",
			set:  func(e *Evidence, v bool) { e.DirectObservation = v },
			get:  func(e Evidence) bool { return e.DirectObservation },
		},
		{
			name: "UnconfirmedByLiveScan",
			set:  func(e *Evidence, v bool) { e.UnconfirmedByLiveScan = v },
			get:  func(e Evidence) bool { return e.UnconfirmedByLiveScan },
		},
		{
			name: "Placeholder",
			set:  func(e *Evidence, v bool) { e.Placeholder = v },
			get:  func(e Evidence) bool { return e.Placeholder },
		},
		{
			// ComponentNotImported is the strongest case for the "no
			// endpoint-derived fallback" warning: it is a fact about the
			// SCANNED TREE (does anything import django.contrib.gis?), which
			// nothing downstream of the scanner can re-observe at all.
			name: "ComponentNotImported",
			set:  func(e *Evidence, v bool) { e.ComponentNotImported = v },
			get:  func(e Evidence) bool { return e.ComponentNotImported },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Round trip: what ToFinding drops, the index puts back.
			in := probeEvidence("GET /admin")
			tc.set(&in, true)

			projected := FromFindings(ToFindings([]Evidence{in}))
			if tc.get(projected[0]) {
				t.Fatalf("guard: %s is supposed to be dropped by the Finding projection —\n"+
					"if it now survives, it has leaked onto the frozen public shape", tc.name)
			}

			restored := NewProvenanceIndex([]Evidence{in}).Restore(projected)
			if !tc.get(restored[0]) {
				t.Errorf("%s did not survive project → restore; the rule that reads it is dead\n"+
					"in production for every caller downstream of the projection", tc.name)
			}

			// 2. Conservative merge: two occurrences of one identity that
			// DISAGREE collapse to false, so a bonus is awarded (and a
			// de-escalation applied) only when every occurrence earned it.
			agree := probeEvidence("GET /admin")
			tc.set(&agree, true)
			disagree := probeEvidence("GET /admin")
			tc.set(&disagree, false)

			mixed := NewProvenanceIndex([]Evidence{agree, disagree}).
				Restore(FromFindings(ToFindings([]Evidence{agree})))
			if tc.get(mixed[0]) {
				t.Errorf("%s survived a dedup group where one occurrence did not carry it —\n"+
					"the merge must be agreementOrBool (logical AND), not OR", tc.name)
			}

			both := NewProvenanceIndex([]Evidence{agree, agree}).
				Restore(FromFindings(ToFindings([]Evidence{agree})))
			if !tc.get(both[0]) {
				t.Errorf("%s was lost in a group where EVERY occurrence carried it — the merge\n"+
					"must be conservative, not just always-false", tc.name)
			}

			// 3. Order independence (F-L6): the fold is a meet, so the index is
			// a pure function of the member SET, not of worker arrival order.
			fwd := NewProvenanceIndex([]Evidence{agree, disagree})
			rev := NewProvenanceIndex([]Evidence{disagree, agree})
			if !reflect.DeepEqual(fwd, rev) {
				t.Errorf("%s merge depends on input order:\n fwd=%+v\n rev=%+v", tc.name, fwd, rev)
			}
		})
	}
}
