package managedci

import (
	"fmt"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// The finding policy's consistency rules, by code
// (contracts/managed-ci/v2/policy/finding-policy-1.0.0.json, `consistency_rules`).
//
// The backend treats a violation as an UNCLASSIFIABLE finding: the submission
// is accepted, the finding is counted in no bucket, and the scan decision
// becomes INCOMPLETE. That is the right answer for contradictory evidence
// arriving from an unknown producer — but for OUR exporter it would mean the
// engine contradicted itself, so the export fails closed instead of shipping
// a finding that can only ever be unclassifiable.
//
// consistency_test.go pins this list against the specification, so a rule
// added canonically cannot be silently unenforced here.
const (
	RuleCrossToolFlagMatchesTools       = "cross_tool_flag_matches_tools"
	RuleProvenPathRequiresRouteAndTaint = "proven_path_requires_route_and_taint"
	RuleDirectObservationRequiresLive   = "direct_observation_requires_live_source"
	RulePayloadValidationRequiresLive   = "payload_validation_requires_live_source"
	RuleSeverityWithinPrecisionCap      = "severity_within_rule_precision_cap"
)

// ConsistencyRules is every rule this package enforces, in specification order.
var ConsistencyRules = []string{
	RuleCrossToolFlagMatchesTools,
	RuleProvenPathRequiresRouteAndTaint,
	RuleDirectObservationRequiresLive,
	RulePayloadValidationRequiresLive,
	RuleSeverityWithinPrecisionCap,
}

// ErrInconsistent names the rule a set of facts violates. It carries no value
// from the scanned code — only the rule code and the finding's identity — so
// it is safe to print in CI output.
type ErrInconsistent struct {
	FindingID string
	Rule      string
}

func (e ErrInconsistent) Error() string {
	return fmt.Sprintf("managed evidence: finding %s violates %s", e.FindingID, e.Rule)
}

// hasRuntime reports whether the facts describe a live observation, which is
// what direct observation and payload validation require.
func (f Facts) hasRuntime() bool {
	return f.ObservationSource == sourceBlackbox || f.ObservationSource == sourceCorrelated
}

// severityCap is the policy's severity_cap_by_rule_precision.
func (f Facts) severityCap() models.Severity {
	switch f.RulePrecision {
	case precisionLow:
		return models.SeverityMedium
	case precisionMedium:
		return models.SeverityHigh
	default:
		return models.SeverityCritical
	}
}

// Consistent reports the first consistency rule these facts violate for a
// finding of the given severity, or nil.
func (f Facts) Consistent(severity models.Severity) error {
	if f.CrossToolCorroborated != (len(f.CorroboratingTools) > 0) {
		return ErrInconsistent{Rule: RuleCrossToolFlagMatchesTools}
	}
	if f.ProvenPath && (!f.RouteConfirmed || !f.ReachableTaintPath || f.AnalyzerImplementation == implSemgrep) {
		return ErrInconsistent{Rule: RuleProvenPathRequiresRouteAndTaint}
	}
	if f.DirectObservation && !f.hasRuntime() {
		return ErrInconsistent{Rule: RuleDirectObservationRequiresLive}
	}
	if f.PayloadValidated && !f.hasRuntime() {
		return ErrInconsistent{Rule: RulePayloadValidationRequiresLive}
	}
	if models.SeverityRank(severity) > models.SeverityRank(f.severityCap()) {
		return ErrInconsistent{Rule: RuleSeverityWithinPrecisionCap}
	}
	return nil
}
