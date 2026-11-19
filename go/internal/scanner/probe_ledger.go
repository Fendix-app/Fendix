package scanner

import (
	"container/heap"
	"fmt"
	"hash/maphash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The probe ledger: the exact, bounded account of the active probes (A-D5,
// OR-13, OR-27, risk R-34).
//
// Hosted scans run with max_endpoints 0, so the number of probes is bounded only
// by the wall clock. Nothing here grows with the probe count:
//
//   - The aggregate counts (attempted, evaluated, and one row per origin x
//     reason x HTTP status) are exact and tiny: the vocabularies are closed.
//   - A probe whose origin depends on evidence that may arrive later (an
//     unknown-origin connect timeout or refusal that the "same host answered
//     within 30 s" clause can move to the target) is held as a count per
//     (host, second, reason) and settled when the account is read, exactly as
//     ClassifyProbe settles it. That map is capped (probePendingMax); past the
//     cap a probe is settled at once as unknown-origin, the fail-closed
//     reading.
//   - Group detail is kept for at most models.ProbeListingCeiling cells, the
//     smallest by a fixed key, so which cells are listed does not depend on the
//     order probes finished in. Every probe whose cell is not kept is counted
//     in ListingOverflow, and the ceiling being reached is declared.
//
// The account is the same whether it is built from a slice of records
// (SummarizeProbes) or streamed as the probes are recorded (the scan-wide
// ProbeAuditLog): both feed the same ledger.

// probePendingMax caps the (host, second, reason) cells awaiting the health
// clause. A scan would need that many distinct seconds of refinable failures
// across its hosts to reach it.
const probePendingMax = 200_000

type countKey struct {
	origin, reason string
	status         int
}

type pendingKey struct {
	host   string
	sec    int64
	reason string
}

// ledgerCell is one (check, endpoint, origin, reason) unit of group detail. A
// pending cell has no origin yet and carries the (host, second) that settles
// it.
type ledgerCell struct {
	key      string
	check    string
	endpoint string
	origin   string // "" while pending
	reason   string
	host     string
	sec      int64
	evidence string // the smallest evidence of the cell's probes
	count    int
	index    int // position in the eviction heap
}

// cellHeap is a max-heap by key: the root is the cell evicted first.
type cellHeap []*ledgerCell

func (h cellHeap) Len() int           { return len(h) }
func (h cellHeap) Less(i, j int) bool { return h[i].key > h[j].key }
func (h cellHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *cellHeap) Push(x any) { c := x.(*ledgerCell); c.index = len(*h); *h = append(*h, c) }
func (h *cellHeap) Pop() any {
	old := *h
	c := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return c
}

type probeLedger struct {
	attempted int
	evaluated int
	counts    map[countKey]int
	pending   map[pendingKey]int
	cells     map[string]*ledgerCell
	order     cellHeap
	ceiling   int
	overflow  int
	reached   bool
}

func newProbeLedger() *probeLedger {
	return &probeLedger{
		counts:  map[countKey]int{},
		pending: map[pendingKey]int{},
		cells:   map[string]*ledgerCell{},
		ceiling: models.ProbeListingCeiling,
	}
}

// statusOf is the HTTP status a not-evaluated row carries: the answer that was
// not evaluable (gated, rate limited, unavailable). Zero otherwise.
func statusOf(r ProbeRecord, v ProbeVerdict) int {
	switch v.Reason {
	case ReasonGated, ReasonRateLimited, ReasonServiceUnavailable:
		if r.Failure == nil {
			return r.Status
		}
	}
	return 0
}

// add accounts for one probe.
func (l *probeLedger) add(r ProbeRecord) {
	l.attempted++
	if f := r.Failure; f != nil && f.Origin == OriginUnknown && f.refinable {
		k := pendingKey{host: strings.ToLower(hostOf(r.Endpoint)), sec: r.Timestamp.Unix(), reason: string(f.Reason)}
		if _, ok := l.pending[k]; ok || len(l.pending) < probePendingMax {
			l.pending[k]++
			l.addCell(checkOfProbe(r), endpointLabel(r), "", string(f.Reason), k.host, k.sec, sanitizeField(f.Evidence, 160))
			return
		}
	}
	v := ClassifyProbe(r, nil)
	if v.Evaluated {
		l.evaluated++
		return
	}
	l.counts[countKey{string(v.Origin), string(v.Reason), statusOf(r, v)}]++
	l.addCell(checkOfProbe(r), endpointLabel(r), string(v.Origin), string(v.Reason), "", 0, sanitizeField(v.Evidence, 160))
}

func (l *probeLedger) addCell(check, endpoint, origin, reason, host string, sec int64, evidence string) {
	tag := origin
	if origin == "" {
		tag = "~" + host + "|" + strconv.FormatInt(sec, 10)
	}
	key := tag + "\x00" + check + "\x00" + endpoint + "\x00" + reason
	if c, ok := l.cells[key]; ok {
		c.count++
		if evidence < c.evidence {
			c.evidence = evidence
		}
		return
	}
	if len(l.cells) >= l.ceiling {
		l.reached = true
		if l.ceiling == 0 || key > l.order[0].key {
			l.overflow++
			return
		}
		out := heap.Pop(&l.order).(*ledgerCell)
		delete(l.cells, out.key)
		l.overflow += out.count
	}
	c := &ledgerCell{key: key, check: check, endpoint: endpoint, origin: origin, reason: reason, host: host, sec: sec, evidence: evidence, count: 1}
	l.cells[key] = c
	heap.Push(&l.order, c)
}

// refinedEvidence is the evidence of an unknown-origin connect failure that
// the health clause moved to the target.
func refinedEvidence(reason ProbeReason) (string, bool) {
	switch reason {
	case ReasonTimeout:
		return "the connect timed out while other requests to this host succeeded within 30s", true
	case ReasonConnectionRefused:
		return "the connection was refused while other requests to this host succeeded within 30s", true
	}
	return "", false
}

// settle is the origin of a pending (host, second) probe: target when the host
// answered something else within the window, unknown otherwise.
func settle(log *ProbeAuditLog, host string, sec int64) ProbeOrigin {
	if log != nil && log.answeredNear(host, time.Unix(sec, 0)) {
		return OriginTarget
	}
	return OriginUnknown
}

var countOriginRank = map[string]int{string(OriginScanner): 0, string(OriginUnknown): 1, string(OriginTarget): 2}

// summary builds the coverage account. log supplies the health evidence that
// settles pending probes (nil: none, so they stay unknown-origin).
func (l *probeLedger) summary(log *ProbeAuditLog) models.ActiveProbeCoverage {
	cov := models.ActiveProbeCoverage{
		Attempted:          l.attempted,
		Evaluated:          l.evaluated,
		Reasons:            map[string]map[string]int{},
		NotEvaluatedChecks: []models.NotEvaluatedCheck{},
		NotEvaluatedCounts: []models.ProbeCountRow{},
		NotEvaluatedGroups: []models.ProbeGroup{},
		Gated:              models.ProbeGated{ByStatus: map[string]int{}},
	}
	counts := make(map[countKey]int, len(l.counts)+4)
	for k, n := range l.counts {
		counts[k] = n
	}
	settled := map[string]ProbeOrigin{} // host|sec -> origin, for the cells
	for k, n := range l.pending {
		o := settle(log, k.host, k.sec)
		settled[k.host+"|"+strconv.FormatInt(k.sec, 10)] = o
		counts[countKey{string(o), k.reason, 0}] += n
	}
	for k, n := range counts {
		switch ProbeOrigin(k.origin) {
		case OriginTarget:
			cov.Inconclusive += n
		case OriginScanner:
			cov.ScannerFailed += n
		default:
			cov.UnknownOrigin += n
		}
		if cov.Reasons[k.origin] == nil {
			cov.Reasons[k.origin] = map[string]int{}
		}
		cov.Reasons[k.origin][k.reason] += n
		if k.origin == string(OriginTarget) && k.reason == string(ReasonGated) {
			cov.Gated.Total += n
			cov.Gated.ByStatus[strconv.Itoa(k.status)] += n
		}
		cov.NotEvaluatedCounts = append(cov.NotEvaluatedCounts, models.ProbeCountRow{Origin: k.origin, Reason: k.reason, Status: k.status, Count: n})
	}
	sort.Slice(cov.NotEvaluatedCounts, func(i, j int) bool {
		a, b := cov.NotEvaluatedCounts[i], cov.NotEvaluatedCounts[j]
		if ra, rb := countOriginRank[a.Origin], countOriginRank[b.Origin]; ra != rb {
			return ra < rb
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Status < b.Status
	})

	// Group detail from the kept cells, each pending cell settled.
	type entryKey struct{ check, endpoint, origin, reason string }
	type groupKey struct{ endpoint, origin, reason string }
	entries := map[entryKey]string{}
	groups := map[groupKey]map[string]bool{}
	for _, c := range l.cells {
		origin, evidence := c.origin, c.evidence
		if origin == "" {
			o := settled[c.host+"|"+strconv.FormatInt(c.sec, 10)]
			if o == "" {
				o = settle(log, c.host, c.sec)
			}
			origin = string(o)
			if o == OriginTarget {
				if ev, ok := refinedEvidence(ProbeReason(c.reason)); ok {
					evidence = sanitizeField(ev, 160)
				}
			}
		}
		ek := entryKey{c.check, c.endpoint, origin, c.reason}
		if cur, ok := entries[ek]; !ok || evidence < cur {
			entries[ek] = evidence
		}
		gk := groupKey{c.endpoint, origin, c.reason}
		if groups[gk] == nil {
			groups[gk] = map[string]bool{}
		}
		groups[gk][c.check] = true
	}

	list := make([]models.NotEvaluatedCheck, 0, len(entries))
	for k, ev := range entries {
		list = append(list, models.NotEvaluatedCheck{Check: k.check, Endpoint: k.endpoint, Origin: k.origin, Reason: k.reason, Evidence: ev})
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if ra, rb := originRank[ProbeOrigin(a.Origin)], originRank[ProbeOrigin(b.Origin)]; ra != rb {
			return ra < rb
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Evidence < b.Evidence
	})
	if len(list) > models.ActiveProbeListCap || l.reached {
		cov.Truncated = len(list) > models.ActiveProbeListCap || l.reached
	}
	if len(list) > models.ActiveProbeListCap {
		list = list[:models.ActiveProbeListCap]
	}
	cov.NotEvaluatedChecks = list

	glist := make([]models.ProbeGroup, 0, len(groups))
	for k, checks := range groups {
		cs := make([]string, 0, len(checks))
		for c := range checks {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		glist = append(glist, models.ProbeGroup{Endpoint: k.endpoint, Origin: k.origin, Reason: k.reason, Checks: cs})
	}
	sort.Slice(glist, func(i, j int) bool {
		a, b := glist[i], glist[j]
		if ra, rb := originRank[ProbeOrigin(a.Origin)], originRank[ProbeOrigin(b.Origin)]; ra != rb {
			return ra < rb
		}
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		return a.Reason < b.Reason
	})
	cov.GroupsTotal = len(glist)
	if len(glist) > models.ProbeInlineGroups {
		cov.InlineTruncated = true
		glist = glist[:models.ProbeInlineGroups]
	}
	cov.NotEvaluatedGroups = glist
	cov.ListingCeilingReached = l.reached
	cov.ListingOverflow = l.overflow
	return cov
}

// ProbeRecordRetention is how many ProbeRecords a log keeps (OR-29). The
// account of every probe is exact regardless (the ledger).
const ProbeRecordRetention = 10_000

// probeStderrBudget is the bytes of per-probe lines a log writes before it
// stops and counts them instead (OR-28). It is 768 KiB, not 1 MiB: the engine's
// whole stderr is what the hosted worker holds (OR-29: 1 MiB), and the lines that
// are not probes (progress, warnings, the summary) need the rest; measured at 600
// endpoints, a 1 MiB probe budget left the whole stderr 6 KiB over the limit.
// probeLineFieldMax caps each target-controlled field of a line, so the budget is
// spent on many probes, not a few long ones.
const (
	probeStderrBudget = 768 << 10
	probeLineFieldMax = 256
)

// ProbeRecordFieldMax caps each target-controlled string a RETAINED record
// holds (its endpoint, parameter, payload and the failure's evidence), so the
// retention bound is a bound in bytes and not only in records (OR-13: a target
// controls the length of every URL the crawler follows). The streaming ledger
// reads the whole record before it is clipped, so no count or classification
// depends on the clip.
const ProbeRecordFieldMax = 1024

// ClipProbeRecord returns r with each long target-controlled field cut to
// ProbeRecordFieldMax bytes and marked with its original length, never
// mid-rune. A record with no long field is returned as it is.
func ClipProbeRecord(r ProbeRecord) ProbeRecord {
	r.Endpoint = clipRetained(r.Endpoint)
	r.Parameter = clipRetained(r.Parameter)
	r.Payload = clipRetained(r.Payload)
	if r.Failure != nil && len(r.Failure.Evidence) > ProbeRecordFieldMax {
		f := *r.Failure
		f.Evidence = clipRetained(f.Evidence)
		r.Failure = &f
	}
	return r
}

func clipRetained(s string) string {
	if len(s) <= ProbeRecordFieldMax {
		return s
	}
	cut := ProbeRecordFieldMax
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(" + strconv.Itoa(len(s)) + " bytes)"
}

var endpointSeed = maphash.MakeSeed()

// endpointHash keys the per-endpoint counts: 8 bytes per endpoint whatever its
// length.
//
// A collision cannot silently change a verdict or let an endpoint past its
// --max-probes-per-endpoint cap (the OR-65 verifier note):
//
//   - Both counts a collision can touch, the probes recorded for an endpoint and
//     the retries sent for it, only ever ADD: two endpoints that share a key share
//     one running total, so each reads at least its own true count. The cap is
//     therefore reached no later than it should be, never later. The cost of a
//     collision is that one endpoint is refused a probe it was entitled to, which
//     is the same silent refusal the cap itself makes (logagg warns "max probes
//     reached").
//   - No verdict reads these counts. The coverage account is the ledger, keyed
//     by the closed origin x reason x status vocabulary and by the group's own
//     strings (never by this hash), so two endpoints cannot merge in it.
//   - The seed is random per process (maphash), so a target cannot pick endpoints
//     that collide; by chance, the odds are n^2 / 2^65 for n endpoints, about 3e-8
//     at a million.
//
// It is a variable so a test can force a collision (probe_collision_wse2_test.go).
var endpointHash = func(endpoint string) uint64 { return maphash.String(endpointSeed, endpoint) }

// probeOutput writes per-probe lines within the budget and counts the rest.
type probeOutput struct {
	verbose bool
	written int
	dropped int
	flushed int
}

func clipField(s string) string {
	if len(s) <= probeLineFieldMax {
		return s
	}
	return s[:probeLineFieldMax] + "...(" + strconv.Itoa(len(s)) + " bytes)"
}

func (o *probeOutput) write(w io.Writer, r ProbeRecord) {
	if w == nil {
		return
	}
	endpoint, param, payload := r.Endpoint, r.Parameter, r.Payload
	if !o.verbose {
		endpoint, param, payload = clipField(endpoint), clipField(param), clipField(payload)
	}
	line := fmt.Sprintf("[PROBE] %s %s type=%s param=%q payload=%q status=%d duration=%s finding=%v\n",
		r.Timestamp.Format(time.RFC3339), endpoint, r.ProbeType, param, payload, r.Status, r.Duration, r.Finding)
	if !o.verbose && o.written+len(line) > probeStderrBudget {
		o.dropped++
		return
	}
	o.written += len(line)
	_, _ = io.WriteString(w, line)
}

// SetVerbose(true) writes every probe line, with every field in full
// (--verbose, OR-28).
func (a *ProbeAuditLog) SetVerbose(v bool) {
	a.mu.Lock()
	a.out.verbose = v
	a.mu.Unlock()
}

// Flush ends the per-probe output: when lines were not written, it writes one
// exact line saying how many (their probes are in the report's counts).
func (a *ProbeAuditLog) Flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := a.out.dropped - a.out.flushed; n > 0 && a.writer != nil {
		fmt.Fprintf(a.writer, "[PROBE] %d further probe lines not written; counts in the report\n", n)
		a.out.flushed = a.out.dropped
	}
}

// Attempted is the number of probes recorded, retained or not.
func (a *ProbeAuditLog) Attempted() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ledger == nil {
		return 0
	}
	return a.ledger.attempted
}

// Retained is the number of records Records returns.
func (a *ProbeAuditLog) Retained() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.records)
}

// TotalFor is how many probes stand behind records: this log's exact total when
// records is what it retained (Records returns only a bounded prefix), and
// len(records) for any other slice. A reader that holds a subset of the log
// uses it to say how much it is not holding.
func (a *ProbeAuditLog) TotalFor(records []ProbeRecord) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ledger != nil && a.ledger.attempted > len(records) && len(a.records) == len(records) {
		return a.ledger.attempted
	}
	return len(records)
}

// Summary is the exact account of every probe this log recorded.
func (a *ProbeAuditLog) Summary() models.ActiveProbeCoverage {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ledger == nil {
		return newProbeLedger().summary(a)
	}
	return a.ledger.summary(a)
}
