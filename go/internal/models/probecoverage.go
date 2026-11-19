package models

// ActiveProbeCoverage is the per-scan account of what the active probes did,
// published as metadata.coverage.active_probes (additive; no schema_version
// change). It exists because a scan-wide "complete" says the analyzer ran, not
// that every probe it sent was evaluated: a probe the target never answered
// proves nothing about whether the vulnerability is there.
//
// Every probe sent falls into exactly one of four groups:
//
//	Evaluated      a response came back and the check judged it
//	Inconclusive   the target gave no evaluable answer, confirmed by evidence
//	               (a reset or stall after the connection was established, a
//	               TLS alert, 429/502/503/504 after the bounded retries, a
//	               redirect into a blocked address, ...) or answered with a
//	               gating status (401, 403, 404 or 410: see Gated); not a
//	               scanner gap, and never evidence that anything is absent
//	UnknownOrigin  no evidence settles who is at fault (DNS failure, a connect
//	               timeout or refusal when the target never answered anything,
//	               network unreachable, ...); fail-closed like a scanner failure
//	ScannerFailed  the engine itself failed or never sent the probe (panic,
//	               its own deadline, local resource exhaustion, a proxy or
//	               request-construction failure, the request budget)
//
// Reasons is {origin: {reason: count}} over the three failure origins
// "target", "unknown" and "scanner". The vocabularies are closed and
// documented with their evidence rules in the header of
// internal/scanner/probe_outcome.go.
type ActiveProbeCoverage struct {
	Attempted     int `json:"attempted"`
	Evaluated     int `json:"evaluated"`
	Inconclusive  int `json:"inconclusive"`
	UnknownOrigin int `json:"unknown_origin"`
	ScannerFailed int `json:"scanner_failed"`
	// Reasons is {origin: {reason: count}}; always present, possibly empty.
	Reasons map[string]map[string]int `json:"reasons"`
	// NotEvaluatedChecks lists, per distinct (check, endpoint, origin, reason),
	// what was not evaluated, capped at ActiveProbeListCap entries.
	NotEvaluatedChecks []NotEvaluatedCheck `json:"not_evaluated_checks"`
	// Truncated is true when NotEvaluatedChecks was cut at the cap. A consumer
	// may treat the list as proof that a (check, endpoint) pair WAS evaluated
	// only when Truncated is false.
	Truncated bool `json:"truncated"`
	// Gated says how many of the Inconclusive probes were answered with a
	// gating status. Always present (zero when none).
	Gated ProbeGated `json:"gated"`
	// CutShort is set when the engine's own --max-duration or --max-requests
	// limit ended the probe pass, so probes it never started are in no count
	// above. Absent when the pass ran to its end.
	CutShort *ProbeCutShort `json:"cut_short,omitempty"`

	// Bounded evidence (A-D5, contract keys OR-10; additive, no schema_version
	// change). Every probe that was not evaluated is accounted for exactly, in
	// storage whose size does not follow the probe count:
	//
	// NotEvaluatedCounts is the exact aggregate: one row per (origin, reason,
	// HTTP status) with a non-zero count, a few dozen rows at most because the
	// vocabularies are closed. The rows add up to Attempted - Evaluated.
	NotEvaluatedCounts []ProbeCountRow `json:"not_evaluated_counts"`
	// NotEvaluatedGroups is at most ProbeInlineGroups groups of (endpoint,
	// origin, reason), each with the checks it covers, in a fixed order.
	NotEvaluatedGroups []ProbeGroup `json:"not_evaluated_groups"`
	// GroupsTotal is the number of groups the engine listed (at most the
	// listing ceiling); InlineTruncated is true when GroupsTotal exceeds the
	// inline groups shown, so every group left out is counted.
	GroupsTotal     int  `json:"groups_total"`
	InlineTruncated bool `json:"inline_truncated"`
	// ListingCeilingReached is true when there were more groups than the
	// engine's hard listing ceiling; ListingOverflow is the exact number of
	// unevaluated probes whose group detail was therefore not recorded. Their
	// counts are in NotEvaluatedCounts all the same. A pass that reached the
	// ceiling is never complete.
	ListingCeilingReached bool `json:"listing_ceiling_reached"`
	ListingOverflow       int  `json:"listing_overflow"`
}

// ProbeCountRow is one cell of the exact not-evaluated aggregate. Status is the
// HTTP status for an answer that was not evaluable (gated 401/403/404/410,
// rate_limited 429, service_unavailable 502/503/504); absent otherwise.
type ProbeCountRow struct {
	Origin string `json:"origin"`
	Reason string `json:"reason"`
	Status int    `json:"status,omitempty"`
	Count  int    `json:"count"`
}

// ProbeGroup is one (endpoint, origin, reason) group of unevaluated probes and
// the rule-id families of the checks those probes belonged to.
type ProbeGroup struct {
	Endpoint string   `json:"endpoint"`
	Origin   string   `json:"origin"`
	Reason   string   `json:"reason"`
	Checks   []string `json:"checks"`
}

// Bounds of the probe evidence (PHASE1-GATE-PROPOSALS 1.4b; starting values
// accepted under OR-29).
const (
	// ProbeInlineGroups is G_inline, the groups shown inline.
	ProbeInlineGroups = 200
	// ProbeListingCeiling is H, the hard ceiling on listed groups. It does not
	// rely on the planner: --max-endpoints 0 removes the endpoint cap.
	ProbeListingCeiling = 100_000
)

// Consistent reports whether the account adds up: no negative count, the
// four groups sum to Attempted, the reasons sum to their origin's count, the
// gated statuses sum to the gated total, and the gated total is the target's
// gated reason and fits inside Inconclusive. An account that does not add up
// is unreadable, and a reader must treat the pass as incomplete.
func (c ActiveProbeCoverage) Consistent() bool {
	for _, n := range []int{c.Attempted, c.Evaluated, c.Inconclusive, c.UnknownOrigin, c.ScannerFailed, c.Gated.Total, c.ListingOverflow, c.GroupsTotal} {
		if n < 0 {
			return false
		}
	}
	if c.Evaluated+c.Inconclusive+c.UnknownOrigin+c.ScannerFailed != c.Attempted {
		return false
	}
	for origin, want := range map[string]int{"target": c.Inconclusive, "unknown": c.UnknownOrigin, "scanner": c.ScannerFailed} {
		sum := 0
		for _, n := range c.Reasons[origin] {
			if n < 0 {
				return false
			}
			sum += n
		}
		if sum != want {
			return false
		}
	}
	byStatus := 0
	for _, n := range c.Gated.ByStatus {
		if n < 0 {
			return false
		}
		byStatus += n
	}
	if byStatus != c.Gated.Total || c.Gated.Total > c.Inconclusive || c.Reasons["target"]["gated"] != c.Gated.Total {
		return false
	}
	if c.NotEvaluatedCounts != nil {
		rows := 0
		for _, r := range c.NotEvaluatedCounts {
			if r.Count < 1 {
				return false
			}
			rows += r.Count
		}
		if rows != c.Attempted-c.Evaluated {
			return false
		}
	}
	return true
}

// NotEvaluated is the number of probes that were not evaluated.
func (c ActiveProbeCoverage) NotEvaluated() int {
	return c.Inconclusive + c.UnknownOrigin + c.ScannerFailed
}

// ProbeGated counts the probes the target answered with 401, 403, 404 or 410.
// A gated probe is NOT evaluated and is evidence of nothing: the answer says
// the request was refused or the path is not served to this client, not that
// the parameter is safe. It is target-side, so it is not a scanner gap and is
// not refunded, and it is counted inside Inconclusive (the account still adds
// up as Attempted = Evaluated + Inconclusive + UnknownOrigin + ScannerFailed).
// Reasons["target"]["gated"] repeats Total.
type ProbeGated struct {
	Total int `json:"total"`
	// ByStatus is {"401": n, "403": n, "404": n, "410": n}, non-zero keys only.
	ByStatus map[string]int `json:"by_status"`
}

// GatedStatuses is the closed list of statuses that gate a probe.
var GatedStatuses = []int{401, 403, 404, 410}

// ProbeCutShort names the limit that ended the active-probe pass. Cause is
// "max_duration" or "max_requests"; Limit is the flag that set it
// ("--max-duration", "--max-requests") and Configured its value as given to the
// engine ("45s", "500"), so a consumer can say the limit was set for the scan
// and by whom it knows it was set. Refused is the number of requests the
// --max-requests budget turned away.
type ProbeCutShort struct {
	Cause      string `json:"cause"`
	Limit      string `json:"limit"`
	Configured string `json:"configured"`
	Refused    int64  `json:"refused"`
}

// ActiveProbeListCap bounds ActiveProbeCoverage.NotEvaluatedChecks.
const ActiveProbeListCap = 200

// NotEvaluatedCheck is one (check, endpoint) pair with a probe that was not
// evaluated. Check is the rule-id family of the findings the probe could have
// produced (injection, xss, ssrf, openredirect, hostheader, graphql,
// methodtamper), Endpoint is "METHOD /path" exactly as a finding names it, and
// Evidence is a fixed phrase stating what was observed.
type NotEvaluatedCheck struct {
	Check    string `json:"check"`
	Endpoint string `json:"endpoint"`
	Origin   string `json:"origin"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
}
