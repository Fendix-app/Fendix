package scanner

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"
)

// Round 6, WS-E2: A-D5 engine half (PHASE1-GATE-PROPOSALS §1.4b, gates G2.9 and
// G2.10). Every unevaluated probe is accounted for, in bounded storage, with no
// silent loss:
//
//   - exact aggregate counts by origin × reason × status, which add up to
//     attempted − evaluated (a few dozen rows at most: the vocabulary is closed);
//   - at most G_inline inline groups of (endpoint, origin, reason) with their
//     check ids, plus groups_total and inline_truncated, so every group left out
//     is counted;
//   - a full group listing under a hard ceiling H; above H the engine stops
//     listing and records listing_ceiling_reached with the exact number of
//     unevaluated probes no listed group holds. --max-endpoints 0 means no
//     endpoint cap, so the ceiling cannot rely on the planner.
//
// Every planned probe is required (OR-23): the engine has no endpoint
// exclusion, and nothing here assumes one.
//
// The tests read the JSON the report carries (ActiveProbeCoverage), so they
// compile against today's struct and fail at run time. The key names below are
// the proposed additive keys of metadata.coverage.active_probes; renaming one
// is a contract decision shared with WS-B1 (the backend stores the same keys).
const (
	wse2KeyCounts          = "not_evaluated_counts"    // [{origin, reason, status, count}]
	wse2KeyGroups          = "not_evaluated_groups"    // inline, at most wse2GInline
	wse2KeyGroupsTotal     = "groups_total"            // distinct (endpoint, origin, reason)
	wse2KeyInlineTruncated = "inline_truncated"        // groups_total > len(inline groups)
	wse2KeyCeiling         = "listing_ceiling_reached" // the full listing stopped at wse2H
	wse2KeyOverflow        = "listing_overflow"        // unevaluated probes in no listed group (exact)

	wse2GInline = 200     // proposed starting value (§1.4b), today's cap
	wse2H       = 100_000 // proposed starting value (§1.4b)
)

func wse2Gated(ep string, status int) ProbeRecord {
	return ProbeRecord{Endpoint: "http://t.example" + ep, Method: "GET", ProbeType: ProbeSQLi, Status: status}
}

func wse2Evaluated(ep string) ProbeRecord {
	return ProbeRecord{Endpoint: "http://t.example" + ep, Method: "GET", ProbeType: ProbeSQLi, Status: 200}
}

func wse2Failed(ep string, origin ProbeOrigin, reason ProbeReason) ProbeRecord {
	return ProbeRecord{Endpoint: "http://t.example" + ep, Method: "GET", ProbeType: ProbeXSS,
		Failure: &ProbeFailure{Origin: origin, Reason: reason, Evidence: "test: " + string(reason)}}
}

// wse2Summary marshals SummarizeProbes exactly as the report does.
func wse2Summary(t *testing.T, recs []ProbeRecord) map[string]any {
	t.Helper()
	blob, err := json.Marshal(SummarizeProbes(recs, nil))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func wse2Int(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("active_probes has no %q (keys: %v)", key, wse2Keys(m))
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("active_probes.%s = %v (%T), want an integer", key, v, v)
	}
	return int(f)
}

func wse2Bool(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("active_probes has no %q (keys: %v)", key, wse2Keys(m))
	}
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("active_probes.%s = %v (%T), want a boolean", key, v, v)
	}
	return b
}

func wse2List(t *testing.T, m map[string]any, key string) []map[string]any {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("active_probes has no %q (keys: %v)", key, wse2Keys(m))
	}
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("active_probes.%s = %T, want an array", key, v)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, x := range raw {
		o, ok := x.(map[string]any)
		if !ok {
			t.Fatalf("active_probes.%s holds %T, want objects", key, x)
		}
		out = append(out, o)
	}
	return out
}

func wse2Keys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// wse2CountRows is {origin/reason/status: count} from the aggregate rows.
func wse2CountRows(t *testing.T, m map[string]any) (map[string]int, int) {
	t.Helper()
	rows := map[string]int{}
	sum := 0
	for _, r := range wse2List(t, m, wse2KeyCounts) {
		n, _ := r["count"].(float64)
		if n < 1 {
			t.Errorf("aggregate row %v has a count below 1", r)
		}
		st, _ := r["status"].(float64)
		k := fmt.Sprintf("%v/%v/%d", r["origin"], r["reason"], int(st))
		if _, dup := rows[k]; dup {
			t.Errorf("aggregate row %s appears twice", k)
		}
		rows[k] = int(n)
		sum += int(n)
	}
	return rows, sum
}

// R5-07 shape: 2,687 attempted, 22 evaluated, 2,665 gated 403 over 533
// endpoints. Counts are exact, 200 groups are inline, and the other 333 are
// counted.
func TestSummarizeProbes_D5_R5_07ShapeCountsEveryUnevaluatedProbe(t *testing.T) {
	var recs []ProbeRecord
	for i := 0; i < 22; i++ {
		recs = append(recs, wse2Evaluated("/open"))
	}
	for e := 0; e < 533; e++ {
		for k := 0; k < 5; k++ {
			recs = append(recs, wse2Gated(fmt.Sprintf("/api/v1/r%03d", e), 403))
		}
	}
	m := wse2Summary(t, recs)
	if a, ev := wse2Int(t, m, "attempted"), wse2Int(t, m, "evaluated"); a != 2687 || ev != 22 {
		t.Fatalf("attempted %d evaluated %d, want 2687/22", a, ev)
	}
	rows, sum := wse2CountRows(t, m)
	if sum != 2665 {
		t.Errorf("aggregate rows add up to %d, want 2665 (attempted − evaluated)", sum)
	}
	if rows["target/gated/403"] != 2665 {
		t.Errorf("target/gated/403 = %d, want 2665 (rows %v)", rows["target/gated/403"], rows)
	}
	if got := wse2Int(t, m, wse2KeyGroupsTotal); got != 533 {
		t.Errorf("groups_total = %d, want 533", got)
	}
	if got := len(wse2List(t, m, wse2KeyGroups)); got != wse2GInline {
		t.Errorf("inline groups = %d, want G_inline = %d", got, wse2GInline)
	}
	if !wse2Bool(t, m, wse2KeyInlineTruncated) {
		t.Error("inline_truncated is false with 533 groups and 200 shown")
	}
	if wse2Bool(t, m, wse2KeyCeiling) {
		t.Error("listing_ceiling_reached with 533 groups")
	}
}

// Below G_inline every group is inline, exactly, and nothing is truncated.
func TestSummarizeProbes_D5_InlineGroupsExactBelowTheCap(t *testing.T) {
	recs := []ProbeRecord{
		wse2Evaluated("/a"), wse2Evaluated("/a"), wse2Evaluated("/b"), wse2Evaluated("/b"),
		wse2Evaluated("/c"), wse2Evaluated("/c"), wse2Evaluated("/c"), wse2Evaluated("/c"),
		wse2Gated("/x", 401), wse2Gated("/y", 404),
	}
	m := wse2Summary(t, recs)
	groups := wse2List(t, m, wse2KeyGroups)
	if len(groups) != 2 || wse2Int(t, m, wse2KeyGroupsTotal) != 2 || wse2Bool(t, m, wse2KeyInlineTruncated) {
		t.Fatalf("groups %v, groups_total %v, inline_truncated %v; want 2, 2, false", groups, m[wse2KeyGroupsTotal], m[wse2KeyInlineTruncated])
	}
	for _, g := range groups {
		for _, f := range []string{"endpoint", "origin", "reason", "checks"} {
			if _, ok := g[f]; !ok {
				t.Errorf("inline group %v has no %q", g, f)
			}
		}
	}
	rows, sum := wse2CountRows(t, m)
	if sum != 2 || rows["target/gated/401"] != 1 || rows["target/gated/404"] != 1 {
		t.Errorf("rows %v (sum %d), want target/gated/401=1 and target/gated/404=1", rows, sum)
	}
}

// --max-endpoints 0 worst case: more groups than the ceiling H. The listing
// stops at H, says so, and counts exactly what it did not list; the aggregate
// counts stay exact. Review B6: every overflow group holds 3 probes, so an
// overflow that counts groups instead of probes (5 instead of 15) fails.
func TestSummarizeProbes_D5_CeilingReachedIsDeclaredAndCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 300,025 probe records")
	}
	const over, perGroup = 5, 3
	recs := make([]ProbeRecord, 0, (wse2H+over)*perGroup+10)
	for i := 0; i < 10; i++ {
		recs = append(recs, wse2Evaluated("/open"))
	}
	for e := 0; e < wse2H+over; e++ {
		for k := 0; k < perGroup; k++ {
			recs = append(recs, wse2Gated(fmt.Sprintf("/e/%06d", e), 403))
		}
	}
	m := wse2Summary(t, recs)
	if _, sum := wse2CountRows(t, m); sum != (wse2H+over)*perGroup {
		t.Errorf("aggregate rows add up to %d, want %d: counts must stay exact past the ceiling", sum, (wse2H+over)*perGroup)
	}
	if !wse2Bool(t, m, wse2KeyCeiling) {
		t.Fatal("listing_ceiling_reached is false with H+5 groups")
	}
	if got := wse2Int(t, m, wse2KeyOverflow); got != over*perGroup {
		t.Errorf("listing_overflow = %d, want exactly %d unevaluated probes in the %d unlisted groups", got, over*perGroup, over)
	}
	if got := len(wse2List(t, m, wse2KeyGroups)); got > wse2GInline {
		t.Errorf("%d inline groups, over G_inline", got)
	}
	// The capped API preview stays as it is (compatibility).
	if n := len(wse2List(t, m, "not_evaluated_checks")); n > 200 || !wse2Bool(t, m, "truncated") {
		t.Errorf("not_evaluated_checks preview: %d entries, truncated %v", n, m["truncated"])
	}
}

// Review B6: the JSON is byte-identical whatever order the probes finished in.
func TestSummarizeProbes_D5_ShuffledRecordsGiveIdenticalJSON(t *testing.T) {
	var recs []ProbeRecord
	for e := 0; e < 400; e++ {
		recs = append(recs, wse2Evaluated(fmt.Sprintf("/ok/%03d", e)), wse2Gated(fmt.Sprintf("/g/%03d", e), []int{401, 403, 404, 410}[e%4]),
			wse2Failed(fmt.Sprintf("/u/%03d", e), OriginUnknown, ReasonDNSFailure), wse2Failed(fmt.Sprintf("/s/%03d", e), OriginScanner, ReasonNotSent))
	}
	want, _ := json.Marshal(SummarizeProbes(recs, nil))
	for seed := uint64(1); seed <= 5; seed++ {
		sh := append([]ProbeRecord(nil), recs...)
		rng := rand.New(rand.NewPCG(seed, 11))
		rng.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		if got, _ := json.Marshal(SummarizeProbes(sh, nil)); string(got) != string(want) {
			t.Fatalf("seed %d: shuffled records give different JSON", seed)
		}
	}
}

// Partial versus total unknown-origin loss (X47/B21 vs the B-17 shape) are told
// apart by exact counts: 10/8/2 and 10/0/10.
func TestSummarizeProbes_D5_PartialAndTotalUnknownLossAreDistinct(t *testing.T) {
	build := func(evaluated, lost int) []ProbeRecord {
		var r []ProbeRecord
		for i := 0; i < evaluated; i++ {
			r = append(r, wse2Evaluated("/a"))
		}
		for i := 0; i < lost; i++ {
			r = append(r, wse2Failed("/a", OriginUnknown, ReasonDNSFailure))
		}
		return r
	}
	for name, c := range map[string]struct{ ev, lost int }{"partial 10/8/2": {8, 2}, "total 10/0/10": {0, 10}} {
		t.Run(name, func(t *testing.T) {
			m := wse2Summary(t, build(c.ev, c.lost))
			if wse2Int(t, m, "attempted") != 10 || wse2Int(t, m, "evaluated") != c.ev || wse2Int(t, m, "unknown_origin") != c.lost {
				t.Fatalf("counts %v", m)
			}
			rows, sum := wse2CountRows(t, m)
			if sum != c.lost || rows["unknown/dns_failure/0"] != c.lost {
				t.Errorf("rows %v (sum %d), want unknown/dns_failure=%d", rows, sum, c.lost)
			}
		})
	}
}

// Every unevaluated probe has a row with a reason, whatever its origin; the
// rows add up to attempted − evaluated.
func TestSummarizeProbes_D5_EveryUnevaluatedProbeHasAReason(t *testing.T) {
	recs := []ProbeRecord{
		wse2Evaluated("/a"),
		wse2Gated("/g1", 401), wse2Gated("/g3", 403), wse2Gated("/g4", 404), wse2Gated("/g10", 410),
		{Endpoint: "http://t.example/rl", Method: "GET", ProbeType: ProbeSQLi, Status: 429, Retries: 2},
		{Endpoint: "http://t.example/su", Method: "GET", ProbeType: ProbeSQLi, Status: 503, Retries: 2},
		wse2Failed("/t", OriginTarget, ReasonTimeout),
		wse2Failed("/u", OriginUnknown, ReasonNetworkUnreachable),
		wse2Failed("/s", OriginScanner, ReasonNotSent),
		wse2Failed("/s", OriginScanner, ReasonInternalError),
		{Endpoint: "http://t.example/z", Method: "GET", ProbeType: ProbeSQLi}, // no status, no evidence
	}
	m := wse2Summary(t, recs)
	rows, sum := wse2CountRows(t, m)
	if want := len(recs) - 1; sum != want {
		t.Errorf("rows add up to %d, want %d: %v", sum, want, rows)
	}
	for _, r := range wse2List(t, m, wse2KeyCounts) {
		if s, _ := r["reason"].(string); s == "" {
			t.Errorf("row without a reason: %v", r)
		}
	}
	for _, k := range []string{"target/gated/401", "target/gated/403", "target/gated/404", "target/gated/410", "target/rate_limited/429", "target/service_unavailable/503"} {
		if rows[k] != 1 {
			t.Errorf("row %s = %d, want 1 (rows %v)", k, rows[k], rows)
		}
	}
}

// OR-60: determinism above the ceiling. Which groups are listed, which
// overflow, and every count must not depend on probe order: the H+5 x 3
// fixture, shuffled with fixed seeds, gives byte-identical JSON.
func TestSummarizeProbes_D5_ShuffledAboveTheCeilingGivesIdenticalJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("summarises 300,025 probe records four times")
	}
	const over, perGroup = 5, 3
	recs := make([]ProbeRecord, 0, (wse2H+over)*perGroup+10)
	for i := 0; i < 10; i++ {
		recs = append(recs, wse2Evaluated("/open"))
	}
	for e := 0; e < wse2H+over; e++ {
		for k := 0; k < perGroup; k++ {
			recs = append(recs, wse2Gated(fmt.Sprintf("/e/%06d", e), []int{401, 403, 404}[k]))
		}
	}
	want, err := json.Marshal(SummarizeProbes(recs, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []uint64{1, 2, 3} {
		sh := append([]ProbeRecord(nil), recs...)
		rand.New(rand.NewPCG(seed, 13)).Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		got, err := json.Marshal(SummarizeProbes(sh, nil))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("seed %d: above the ceiling, shuffled records give different JSON", seed)
		}
	}
}
