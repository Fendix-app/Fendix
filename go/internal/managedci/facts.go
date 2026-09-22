// Package managedci exports managed-CI evidence under the canonical contract
// managed-ci/v2 (contracts/managed-ci/v2).
//
// What this package is FOR: the backend classifies a managed submission by
// interpreting the canonical finding policy over normalized evidence FACTS.
// This package is the production producer of those facts. It reads the
// engine's own domain objects — the same evidence.Evidence the confidence
// scorer and the decision layer read — and reports what was OBSERVED.
//
// What this package must never do: export a conclusion. No confidence score,
// no band, no tier, no status, no decision, no exit code, no blocking claim,
// and nothing derived from the runner's own --fail-on. The contract rejects
// such keys outright, and the whole point of the managed lane is that the
// backend, not the runner, decides. `payload_validated` exists precisely so a
// probe exchange never leaves the runner.
//
// Parity: facts_test.go replays every canonical policy vector through
// FactsFrom and requires the exported facts to be identical to the vector's,
// so the exporter cannot drift from the policy the engine implements and the
// backend interprets.
package managedci

import (
	"fmt"
	"sort"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Facts is the closed 17-fact vocabulary of
// contracts/managed-ci/v2/schemas/evidence-facts.schema.json.
//
// Field order is the schema's alphabetical order, so encoding/json emits a
// byte-identical object for identical input (Go marshals struct fields in
// declaration order). Every field is always emitted: the finding policy makes
// all 17 mandatory, and an absent fact makes the finding unclassifiable
// rather than "assumed false".
type Facts struct {
	AnalyzerImplementation  string   `json:"analyzer_implementation"`
	AuthExpectation         string   `json:"auth_expectation"`
	CorroboratingTools      []string `json:"corroborating_tools"`
	CrossToolCorroborated   bool     `json:"cross_tool_corroborated"`
	DependencyApplicability string   `json:"dependency_applicability"`
	DirectObservation       bool     `json:"direct_observation"`
	FixtureShapedValue      bool     `json:"fixture_shaped_value"`
	InTestCode              bool     `json:"in_test_code"`
	ObservationSource       string   `json:"observation_source"`
	PayloadValidated        bool     `json:"payload_validated"`
	ProvenPath              bool     `json:"proven_path"`
	ProviderAnchoredSecret  bool     `json:"provider_anchored_secret"`
	ReachableTaintPath      bool     `json:"reachable_taint_path"`
	ResponseContext         string   `json:"response_context"`
	RouteConfirmed          bool     `json:"route_confirmed"`
	RulePrecision           string   `json:"rule_precision"`
	UnconfirmedByLiveScan   bool     `json:"unconfirmed_by_live_scan"`
}

// Enum values, exactly as the schema declares them.
const (
	implNative      = "native"
	implTreeSitter  = "tree_sitter"
	implSemgrep     = "semgrep"
	implUnspecified = "unspecified"

	sourceWhitebox   = "whitebox"
	sourceBlackbox   = "blackbox"
	sourceCorrelated = "correlated"
	sourceImported   = "imported"

	applicabilityUnknown         = "unknown"
	applicabilityApplicable      = "applicable"
	applicabilityEvidenceAgainst = "evidence_against"

	authUnknown  = "unknown"
	authPublic   = "public"
	authRequired = "required"

	contextNone        = "none"
	contextClientError = "client_error_4xx"
	contextStaticAsset = "static_asset"

	precisionHigh   = "high"
	precisionMedium = "medium"
	precisionLow    = "low"
)

// ErrUnmappable reports engine state the contract vocabulary cannot express.
// It is returned, never guessed around: a fabricated fact would be a false
// attestation about the scanned code.
type ErrUnmappable struct {
	Field string
	Value string
}

func (e ErrUnmappable) Error() string {
	return fmt.Sprintf("managed evidence: %s has no contract value for %q", e.Field, e.Value)
}

// FactsFrom reports what the engine observed about one piece of evidence.
//
// Every fact reads exactly one engine field, and the fields are the same ones
// confidence.Score and decision.DecideWithOptions read, so the exported facts
// describe the evidence the engine itself scored. Call it AFTER
// ProvenanceIndex.Restore, or the internal half (probe exchange, response
// context, test-code and producer flags) is still detached and the facts will
// understate what was observed.
func FactsFrom(ev evidence.Evidence) (Facts, error) {
	source, err := observationSource(ev.Source)
	if err != nil {
		return Facts{}, err
	}
	precision, err := rulePrecision(ev.Confidence)
	if err != nil {
		return Facts{}, err
	}
	responseContext, err := responseContextOf(ev.ResponseContext)
	if err != nil {
		return Facts{}, err
	}
	auth, err := authExpectation(ev.AuthExpectation)
	if err != nil {
		return Facts{}, err
	}
	applicability, err := dependencyApplicability(ev)
	if err != nil {
		return Facts{}, err
	}
	return Facts{
		AnalyzerImplementation: analyzerImplementation(ev.SourceTier),
		AuthExpectation:        auth,
		CorroboratingTools:     corroboratingTools(ev.CorroboratingTools),
		CrossToolCorroborated:  ev.CrossToolCorroborated,
		// The probe request and its reply never leave the runner; only the
		// fact that the predicted response arrived does.
		PayloadValidated:        ev.Payload != "" && ev.Response != "",
		DependencyApplicability: applicability,
		DirectObservation:       ev.DirectObservation,
		FixtureShapedValue:      ev.Placeholder,
		InTestCode:              ev.InTest,
		ObservationSource:       source,
		ProvenPath:              ev.ProvenPath,
		ProviderAnchoredSecret:  ev.ProviderAnchored,
		ReachableTaintPath:      ev.Reachable,
		ResponseContext:         responseContext,
		RouteConfirmed:          ev.RouteConfirmed,
		RulePrecision:           precision,
		UnconfirmedByLiveScan:   ev.UnconfirmedByLiveScan,
	}, nil
}

// analyzerImplementation: an unset tier is "unspecified", which the
// vocabulary carries deliberately — it is the honest answer when a scanner
// did not declare its implementation class.
func analyzerImplementation(tier models.SourceTier) string {
	switch tier {
	case models.TierNativeGo:
		return implNative
	case models.TierTreeSitter:
		return implTreeSitter
	case models.TierSemgrepShim:
		return implSemgrep
	default:
		return implUnspecified
	}
}

func observationSource(source models.Source) (string, error) {
	switch source {
	case models.SourceWhitebox:
		return sourceWhitebox, nil
	case models.SourceBlackbox:
		return sourceBlackbox, nil
	case models.SourceCorrelated:
		return sourceCorrelated, nil
	case models.SourceImported:
		return sourceImported, nil
	default:
		return "", ErrUnmappable{Field: "observation_source", Value: string(source)}
	}
}

func rulePrecision(confidence models.Confidence) (string, error) {
	switch confidence {
	case models.ConfidenceHigh:
		return precisionHigh, nil
	case models.ConfidenceMedium:
		return precisionMedium, nil
	case models.ConfidenceLow:
		return precisionLow, nil
	default:
		return "", ErrUnmappable{Field: "rule_precision", Value: string(confidence)}
	}
}

func responseContextOf(tag string) (string, error) {
	switch tag {
	case "":
		return contextNone, nil
	case "4xx":
		return contextClientError, nil
	case "static-asset":
		return contextStaticAsset, nil
	default:
		return "", ErrUnmappable{Field: "response_context", Value: tag}
	}
}

func authExpectation(expectation models.AuthExpectation) (string, error) {
	switch expectation {
	case models.AuthExpectationUnknown:
		return authUnknown, nil
	case models.AuthExpectationPublic:
		return authPublic, nil
	case models.AuthExpectationRequired:
		return authRequired, nil
	default:
		return "", ErrUnmappable{Field: "auth_expectation", Value: string(expectation)}
	}
}

// dependencyApplicability reads the three-state verdict, and honours the
// superseded ComponentNotImported flag alongside it: the scorer still applies
// its penalty, so a producer that sets only the old flag must not be exported
// as "unknown". Either marker alone means the same observation.
func dependencyApplicability(ev evidence.Evidence) (string, error) {
	switch ev.Applicability {
	case models.ApplicabilityEvidenceAgainst:
		return applicabilityEvidenceAgainst, nil
	case models.ApplicabilityApplicable:
		return applicabilityApplicable, nil
	case models.ApplicabilityUnknown:
		if ev.ComponentNotImported {
			return applicabilityEvidenceAgainst, nil
		}
		return applicabilityUnknown, nil
	default:
		return "", ErrUnmappable{Field: "dependency_applicability", Value: string(ev.Applicability)}
	}
}

// corroboratingTools returns a sorted, de-duplicated, never-nil list: the
// document must be byte-identical for identical observations, and the schema
// requires unique items. Empty stays an empty array, never null.
func corroboratingTools(tools []string) []string {
	if len(tools) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))
	for _, tool := range tools {
		if tool == "" {
			continue
		}
		if _, dup := seen[tool]; dup {
			continue
		}
		seen[tool] = struct{}{}
		out = append(out, tool)
	}
	sort.Strings(out)
	return out
}
