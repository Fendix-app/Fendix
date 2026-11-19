package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Round 6, WS-E2: OR-13 / OR-27 / OR-28 / OR-50 (risk R-34, the A-D5
// memory-safety condition).
//
// ProbeAuditLog keeps every ProbeRecord it is given (injection.go: records
// []ProbeRecord), the scan-wide log lives for the whole run, and hosted
// dashboard scans default to max_endpoints 0 (backend serializers.py:1473), so
// the engine's memory is bounded only by the wall clock. The contract pinned
// here (OR-27): bounded records, exact streaming counters, a per-endpoint count
// map in place of the O(N) Count(), and bounded bytes, not only bounded counts,
// because endpoints are target-controlled strings. OR-28: per-probe stderr
// lines up to a fixed budget, then one exact summary line; --verbose restores
// every line.
//
// Starting bounds (OR-29): 10,000 records, 4 MiB heap slack, 1 MiB stderr.

const (
	wse2RetainBound = 10_000
	wse2HeapSlack   = 4 << 20
	wse2StderrBytes = 1 << 20
	wse2Ceiling     = 100_000 // H, as in probe_ledger_round6_test.go
)

// wse2Install makes log the scan-wide log. The caller resets it.
func wse2Install(log *ProbeAuditLog) {
	globalAuditMu.Lock()
	globalAuditLog = log
	globalAuditMu.Unlock()
}

// wse2Probe is a synthetic probe on endpoint e (1 in 50 evaluated, the rest gated 403).
func wse2Probe(i, endpoints int) ProbeRecord {
	status := 403
	if i%50 == 0 {
		status = 200
	}
	return ProbeRecord{
		Endpoint:  fmt.Sprintf("http://t.example/e/%06d?id=1", i%endpoints),
		Method:    "GET",
		ProbeType: ProbeSQLi,
		Parameter: "id",
		Payload:   "' OR '1'='1' -- " + fmt.Sprint(i%7),
		Status:    status,
		Duration:  "3ms",
	}
}

// wse2FillGlobal installs a quiet scan-wide log holding n probes over the given
// number of endpoints, and returns it.
func wse2FillGlobal(n, endpoints int) *ProbeAuditLog {
	log := NewProbeAuditLogWithWriter(io.Discard)
	wse2Install(log)
	for i := 0; i < n; i++ {
		log.Record(wse2Probe(i, endpoints))
	}
	return log
}

func wse2RetainedHeap(fill func() any) uint64 {
	ResetGlobalAuditLog()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	keep := fill()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(keep)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

func TestProbeAuditLog_OR13_RetainedRecordsAreBoundedAndCountsExact(t *testing.T) {
	const n = 100_000
	defer ResetGlobalAuditLog()
	wse2FillGlobal(n, 25_000)

	if got := len(GlobalAuditRecords()); got > wse2RetainBound {
		t.Errorf("the scan-wide probe log retains %d ProbeRecords after %d probes; it must hold at most a fixed %d whatever the probe count (R-34)", got, n, wse2RetainBound)
	}
	cov := SummarizeGlobalProbes()
	wantEval := (n + 49) / 50
	if cov.Attempted != n || cov.Evaluated != wantEval || cov.Inconclusive != n-wantEval {
		t.Errorf("counts not exact: attempted %d evaluated %d inconclusive %d, want %d/%d/%d", cov.Attempted, cov.Evaluated, cov.Inconclusive, n, wantEval, n-wantEval)
	}
	if cov.Gated.Total != n-wantEval || cov.Gated.ByStatus["403"] != n-wantEval {
		t.Errorf("gated counts not exact: total %d by_status %v, want %d", cov.Gated.Total, cov.Gated.ByStatus, n-wantEval)
	}
}

// Review W2: the probe count grows, the endpoint (group) count does not. The
// retained heap may not follow the probe count.
func TestProbeAuditLog_OR13_RetainedHeapIsIndependentOfProbeCount(t *testing.T) {
	defer ResetGlobalAuditLog()
	const endpoints = 1_000
	small := wse2RetainedHeap(func() any { return wse2FillGlobal(20_000, endpoints) })
	large := wse2RetainedHeap(func() any { return wse2FillGlobal(100_000, endpoints) })
	if large > small+wse2HeapSlack {
		t.Errorf("with %d endpoints held constant, retained heap grows with the probe count: %d KiB at 20,000 probes, %d KiB at 100,000 (+%d B per extra probe)",
			endpoints, small>>10, large>>10, (large-small)/80_000)
	}
}

// Review W2, second half: per-group memory is allowed up to the listing
// ceiling H and not past it. 2H groups retain what H groups retain, plus slack.
func TestProbeAuditLog_OR13_GroupMemoryStopsAtTheCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("records 200,000 probes")
	}
	defer ResetGlobalAuditLog()
	atH := wse2RetainedHeap(func() any { return wse2FillGlobal(wse2Ceiling, wse2Ceiling) })
	at2H := wse2RetainedHeap(func() any { return wse2FillGlobal(2*wse2Ceiling, 2*wse2Ceiling) })
	if at2H > atH+wse2HeapSlack {
		t.Errorf("groups past the ceiling still cost memory: %d KiB at H=%d groups, %d KiB at 2H (+%d B per group past H)",
			atH>>10, wse2Ceiling, at2H>>10, (at2H-atH)/wse2Ceiling)
	}
}

// OR-50: the retries map is keyed by the full endpoint URL, which the target
// controls. A thousand 64 KiB endpoints may not pin 64 MiB: bound bytes, not
// only entries. The per-endpoint count stays exact.
func TestProbeAuditLog_OR13_RetriesMapBytesAreBounded(t *testing.T) {
	defer ResetGlobalAuditLog()
	// OR-60: the endpoints differ only in their last bytes, so a bound that
	// keeps a prefix would merge them and break the per-endpoint count.
	long := func(i int) string { return "http://t.example/" + strings.Repeat("a", 64<<10) + fmt.Sprintf("%06d", i) }
	var log *ProbeAuditLog
	heap := wse2RetainedHeap(func() any {
		log = NewProbeAuditLogWithWriter(io.Discard)
		for i := 0; i < 1_000; i++ {
			log.noteRetry(long(i))
		}
		return log
	})
	if heap > wse2HeapSlack {
		t.Errorf("1,000 retries on 64 KiB target-controlled endpoints retain %d KiB; the retry state must be bounded in bytes", heap>>10)
	}
	for _, i := range []int{7, 8, 999} {
		if got := log.Count(long(i)); got != 1 {
			t.Errorf("Count(long endpoint %d) = %d after one retry, want 1 (the per-endpoint budget must stay exact)", i, got)
		}
	}
}

// OR-50: the transient grouping map in SummarizeProbes (byKey) grows with the
// number of distinct groups. Past the ceiling H the summary's live working
// memory may not keep growing. OR-60: measured with the collector at
// GOGC=1, so HeapAlloc tracks the live heap rather than garbage awaiting a
// default-GOGC cycle, comparing 4H with H as growth per group past H.
func TestSummarizeProbes_OR13_PeakMemoryStopsAtTheCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("summarises 400,000 groups")
	}
	prev := debug.SetGCPercent(1)
	defer debug.SetGCPercent(prev)
	peak := func(groups int) uint64 {
		recs := make([]ProbeRecord, groups)
		for i := range recs {
			recs[i] = ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/g/%07d", i), Method: "GET", ProbeType: ProbeSQLi, Status: 403}
		}
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		var max atomic.Uint64
		done := make(chan struct{})
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			var m runtime.MemStats
			for {
				select {
				case <-done:
					return
				default:
				}
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > max.Load() {
					max.Store(m.HeapAlloc)
				}
				time.Sleep(time.Millisecond)
			}
		}()
		cov := SummarizeProbes(recs, nil)
		close(done)
		<-stopped
		runtime.KeepAlive(recs)
		runtime.KeepAlive(cov)
		if max.Load() < base.HeapAlloc {
			return 0
		}
		return max.Load() - base.HeapAlloc
	}
	atH, at4H := peak(wse2Ceiling), peak(4*wse2Ceiling)
	var perGroup uint64
	if at4H > atH {
		perGroup = (at4H - atH) / (3 * wse2Ceiling)
	}
	const maxPerGroup = 32 // bytes of live working memory per group past H
	if perGroup > maxPerGroup {
		t.Errorf("SummarizeProbes' live working memory keeps growing past the ceiling: %d KiB at H groups, %d KiB at 4H (%d B per group past H, limit %d)",
			atH>>10, at4H>>10, perGroup, maxPerGroup)
	}
}

// OR-50: Count(endpoint) scans every record (O(N) per call, so O(N²) over a
// scan that checks the per-endpoint budget for each probe). OR-27 replaces it
// with a per-endpoint map: the cost per call may not follow the record count.
func TestProbeAuditLog_OR13_CountIsNotLinearInTheRecordCount(t *testing.T) {
	defer ResetGlobalAuditLog()
	cost := func(n int) time.Duration {
		log := wse2FillGlobal(n, n/4)
		best := time.Duration(1<<63 - 1)
		for rep := 0; rep < 3; rep++ {
			start := time.Now()
			for i := 0; i < 1_000; i++ {
				log.Count(fmt.Sprintf("http://t.example/e/%06d?id=1", i%(n/4)))
			}
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	small, large := cost(1_000), cost(100_000)
	if small <= 0 {
		small = time.Microsecond
	}
	if ratio := float64(large) / float64(small); ratio > 10 {
		t.Errorf("1,000 Count calls take %s at 1,000 records and %s at 100,000 (x%.0f): Count is linear in the record count (O(N^2) per scan)", small, large, ratio)
	}
}

// Neighbour that must keep passing: the per-endpoint budget stays exact.
func TestProbeAuditLog_OR13_PerEndpointCountStaysExact(t *testing.T) {
	defer ResetGlobalAuditLog()
	log := wse2FillGlobal(100_000, 25_000)
	for _, ep := range []string{"http://t.example/e/000000?id=1", "http://t.example/e/012345?id=1", "http://t.example/e/024999?id=1"} {
		if got := log.Count(ep); got != 4 {
			t.Errorf("Count(%s) = %d, want 4", ep, got)
		}
	}
}

// ---- Review B5: the bounded summary equals the full one --------------------

// wse2Population is a mixed account: every origin, the gated statuses, retried
// 429/503, unclassified records, and refinable unknown-origin connect timeouts,
// some of which a LATER answer from the same host refines to target (the "same
// host succeeded within 30 s" clause, settled at summary time). The B-17 refund
// boundary depends on that split, so the bounded summary must agree exactly.
func wse2Population(log *ProbeAuditLog, n int) []ProbeRecord {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var all []ProbeRecord
	add := func(r ProbeRecord) { log.Record(r); all = append(all, r) }
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * time.Millisecond)
		ep := fmt.Sprintf("http://h%d.example/e/%05d", i%3, i%4000)
		switch i % 11 {
		case 0, 1:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeSQLi, Status: 200})
		case 2:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeXSS, Status: []int{401, 403, 404, 410}[i%4]})
		case 3:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "POST", ProbeType: ProbeSQLi, Status: []int{429, 502, 503, 504}[i%4], Retries: 2})
		case 4:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeSSRF,
				Failure: &ProbeFailure{Origin: OriginTarget, Reason: ReasonConnectionReset, Evidence: "reset after connect"}})
		case 5:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeSQLi,
				Failure: &ProbeFailure{Origin: OriginUnknown, Reason: ReasonDNSFailure, Evidence: "no such host"}})
		case 6:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeSQLi,
				Failure: &ProbeFailure{Origin: OriginScanner, Reason: ReasonNotSent, Evidence: "budget"}})
		case 7:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeSQLi}) // unclassified
		default:
			add(ProbeRecord{Timestamp: ts, Endpoint: ep, Method: "GET", ProbeType: ProbeRedirect,
				Failure: &ProbeFailure{Origin: OriginUnknown, Reason: ReasonTimeout, Evidence: "connect timeout", refinable: true}})
		}
	}
	wse2LateAnswers(log, n)
	return all
}

// wse2LateAnswers notes, after every record, that hosts h0 and h1 answered (every
// 20 s across the span); h2 never answers.
func wse2LateAnswers(log *ProbeAuditLog, n int) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	span := int(time.Duration(n)*time.Millisecond/time.Second) + 1
	for s := 0; s < span; s += 20 {
		log.NoteTargetResponse("h0.example", t0.Add(time.Duration(s)*time.Second))
		log.NoteTargetResponse("h1.example", t0.Add(time.Duration(s)*time.Second))
	}
}

func wse2JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wse2PopulationAccount is the exact account of wse2Population(log, 30000),
// without the capped not_evaluated_checks preview.
const wse2PopulationAccount = `{"attempted":30000,"evaluated":5456,"inconclusive":13636,"unknown_origin":8181,"scanner_failed":2727,` +
	`"reasons":{"scanner":{"not_sent":2727},"target":{"connection_reset":2727,"gated":2728,"rate_limited":681,"service_unavailable":2046,"timeout":5454},` +
	`"unknown":{"dns_failure":2727,"timeout":2727,"unclassified":2727}},` +
	`"gated":{"by_status":{"401":682,"403":682,"404":682,"410":682},"total":2728}}`

// wse2Counts is the account's counting keys only, as compact JSON in a fixed
// order (the D5 keys added in Stage B are compared by the equality check).
func wse2Counts(t *testing.T, v any) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(wse2JSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("{")
	for i, k := range []string{"attempted", "evaluated", "inconclusive", "unknown_origin", "scanner_failed", "reasons", "gated"} {
		if i > 0 {
			b.WriteString(",")
		}
		var x any
		_ = json.Unmarshal(m[k], &x)
		raw, _ := json.Marshal(x)
		fmt.Fprintf(&b, "%q:%s", k, raw)
	}
	b.WriteString("}")
	return b.String()
}

func TestSummarizeGlobalProbes_B5_BoundedSummaryEqualsTheFullOne(t *testing.T) {
	defer ResetGlobalAuditLog()
	log := NewProbeAuditLogWithWriter(io.Discard)
	wse2Install(log)
	// More than the retention bound, so a bounded log is exercised.
	all := wse2Population(log, 3*wse2RetainBound)
	full := SummarizeProbes(all, log)
	if full.Inconclusive == 0 || full.UnknownOrigin == 0 || full.Reasons["target"]["timeout"] == 0 {
		t.Fatalf("fixture error: the population did not refine any timeout to target: %+v", full.Reasons)
	}
	bounded := SummarizeGlobalProbes()
	// OR-60: equality alone compares the function with itself today. The
	// account is also pinned: captured at f438bc3, it follows from the
	// population (3 of every 11 probes are refinable connect timeouts; those on
	// h0 and h1, which answer later, are target-side, those on h2 stay
	// unknown). A rewrite that moves the unknown/target split fails here.
	for name, got := range map[string]any{"full": full, "bounded": bounded} {
		if a := wse2Counts(t, got); a != wse2PopulationAccount {
			t.Errorf("%s account changed:\nwant %s\ngot  %s", name, wse2PopulationAccount, a)
		}
	}
	if a, b := wse2JSON(t, full), wse2JSON(t, bounded); !bytes.Equal(a, b) {
		t.Errorf("the scan-wide summary differs from the summary of every record (B-17 refund boundary):\nfull    %s\nbounded %s", a, b)
	}
}

// Review B6: the account does not depend on the order probes finished in.
func TestSummarizeGlobalProbes_B6_ShuffledRecordsGiveIdenticalJSON(t *testing.T) {
	defer ResetGlobalAuditLog()
	ref := NewProbeAuditLogWithWriter(io.Discard)
	wse2Install(ref)
	all := wse2Population(ref, 3*wse2RetainBound)
	want := wse2JSON(t, SummarizeGlobalProbes())
	for seed := uint64(1); seed <= 3; seed++ {
		shuffled := append([]ProbeRecord(nil), all...)
		rng := rand.New(rand.NewPCG(seed, 7))
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		log := NewProbeAuditLogWithWriter(io.Discard)
		wse2Install(log)
		for _, r := range shuffled {
			log.Record(r)
		}
		wse2LateAnswers(log, len(all))
		if got := wse2JSON(t, SummarizeGlobalProbes()); !bytes.Equal(got, want) {
			t.Errorf("seed %d: shuffled records give a different account:\nwant %s\ngot  %s", seed, want, got)
		}
		if got := wse2JSON(t, SummarizeProbes(shuffled, log)); !bytes.Equal(got, want) {
			t.Errorf("seed %d: SummarizeProbes over shuffled records differs", seed)
		}
	}
}

// ---- Review W3 / OR-28: bounded stderr with one exact summary line ----------

var wse2SummaryLine = regexp.MustCompile(`(\d+) further probe lines not written; counts in the report`)

type wse2CountingWriter struct {
	n   int
	buf bytes.Buffer
	cap int
}

func (c *wse2CountingWriter) Write(p []byte) (int, error) {
	c.n += len(p)
	if c.buf.Len() < c.cap {
		c.buf.Write(p[:min(len(p), c.cap-c.buf.Len())])
	}
	return len(p), nil
}

// wse2Call calls a no-argument method by name, or fails naming the missing seam.
func wse2Call(t *testing.T, log *ProbeAuditLog, name string, args ...any) {
	t.Helper()
	m := reflect.ValueOf(log).MethodByName(name)
	if !m.IsValid() {
		t.Fatalf("OR-28: *ProbeAuditLog has no %s method (the seam this test expects for the stderr budget)", name)
	}
	in := make([]reflect.Value, len(args))
	for i, a := range args {
		in[i] = reflect.ValueOf(a)
	}
	m.Call(in)
}

func wse2ProbeLines(out string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[PROBE] ") && strings.Contains(l, " type=") {
			n++
		}
	}
	return n
}

// The default: per-probe lines up to the budget, then, when the pass ends
// (Flush), one exact line saying how many were not written. Deleting the output
// does not pass: the summary line and its exact count are required.
func TestProbeAuditLog_OR28_StderrIsBoundedWithAnExactSummaryLine(t *testing.T) {
	const n = 100_000
	w := &wse2CountingWriter{cap: 4 << 20}
	log := NewProbeAuditLogWithWriter(w)
	for i := 0; i < n; i++ {
		log.Record(wse2Probe(i, 25_000))
	}
	if w.n > wse2StderrBytes {
		t.Errorf("the probe log wrote %d KiB for %d probes (%d B per probe); OR-28 caps it at %d KiB", w.n>>10, n, w.n/n, wse2StderrBytes>>10)
	}
	wse2Call(t, log, "Flush")
	out := w.buf.String()
	written := wse2ProbeLines(out)
	m := wse2SummaryLine.FindAllStringSubmatch(out, -1)
	if len(m) != 1 {
		t.Fatalf("want exactly one summary line, found %d", len(m))
	}
	if m[0][1] != fmt.Sprint(n-written) {
		t.Errorf("summary says %s further lines, but %d of %d probe lines were written (want %d)", m[0][1], written, n, n-written)
	}
}

// --verbose restores every line (OR-28) and needs no summary.
func TestProbeAuditLog_OR28_VerboseWritesEveryLine(t *testing.T) {
	const n = 20_000
	w := &wse2CountingWriter{cap: 64 << 20}
	log := NewProbeAuditLogWithWriter(w)
	wse2Call(t, log, "SetVerbose", true)
	for i := 0; i < n; i++ {
		log.Record(wse2Probe(i, 5_000))
	}
	wse2Call(t, log, "Flush")
	if got := wse2ProbeLines(w.buf.String()); got != n {
		t.Errorf("--verbose wrote %d of %d probe lines", got, n)
	}
	if wse2SummaryLine.MatchString(w.buf.String()) {
		t.Error("--verbose wrote a 'further probe lines not written' summary although every line was written")
	}
}

// Bytes, not lines: target-controlled 64 KiB endpoints and payloads may not
// carry the output past the budget, and the summary stays exact.
func TestProbeAuditLog_OR28_LongTargetControlledEndpointsAreBoundedInBytes(t *testing.T) {
	const n = 2_000
	w := &wse2CountingWriter{cap: 8 << 20}
	log := NewProbeAuditLogWithWriter(w)
	pad := strings.Repeat("A", 64<<10)
	for i := 0; i < n; i++ {
		log.Record(ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/%05d/%s", i, pad), Method: "GET", ProbeType: ProbeSQLi,
			Parameter: "id", Payload: pad, Status: 403, Duration: "3ms"})
	}
	if w.n > wse2StderrBytes {
		t.Errorf("%d probes on 64 KiB endpoints wrote %d KiB; the budget is %d KiB of bytes, whatever a line's length", n, w.n>>10, wse2StderrBytes>>10)
	}
	wse2Call(t, log, "Flush")
	out := w.buf.String()
	m := wse2SummaryLine.FindStringSubmatch(out)
	if m == nil || m[1] != fmt.Sprint(n-wse2ProbeLines(out)) {
		t.Errorf("summary line %q does not count the %d unwritten probe lines exactly", m, n-wse2ProbeLines(out))
	}
}
