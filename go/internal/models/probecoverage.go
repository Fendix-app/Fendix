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
//	Inconclusive   the target did not answer, confirmed by evidence (a reset
//	               or stall after the connection was established, a TLS alert,
//	               429/502/503/504 after the bounded retries, ...); not a
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
