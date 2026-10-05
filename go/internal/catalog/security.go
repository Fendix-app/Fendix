// Package catalog projects executable registries into the public
// documentation contract. It contains no editorial copy.
package catalog

import (
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scanner/textscan"
)

const (
	SchemaVersion       = 1
	StableEngineVersion = "v3.5.1"
)

type Contract struct {
	SchemaVersion int              `json:"schema_version"`
	EngineVersion string           `json:"engine_version"`
	Checks        []Check          `json:"checks"`
	Analyzers     []Analyzer       `json:"analyzers"`
	Coverage      CoverageContract `json:"coverage"`
}

type Check struct {
	ID              string   `json:"id"`
	FindingID       string   `json:"finding_id,omitempty"`
	Title           string   `json:"title,omitempty"`
	Analyzer        string   `json:"analyzer"`
	Category        string   `json:"category"`
	DefaultSeverity string   `json:"default_severity,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	CWEs            []string `json:"cwes"`
	ExecutionMode   string   `json:"execution_mode"`
	AuthRequirement string   `json:"auth_requirement"`
	Applicability   []string `json:"applicability"`
	Remediation     string   `json:"remediation,omitempty"`
	Availability    string   `json:"availability"`
}

type Analyzer struct {
	ID                string `json:"id"`
	BaseStatus        bool   `json:"base_status"`
	ProtocolDependent bool   `json:"protocol_dependent"`
	Availability      string `json:"availability"`
}

type CoverageContract struct {
	ContractVersion int              `json:"contract_version"`
	RawStates       []string         `json:"raw_states"`
	Classes         []CoverageClass  `json:"classes"`
	Reasons         []CoverageReason `json:"reasons"`
}

type CoverageClass struct {
	ID                string `json:"id"`
	EngineGap         bool   `json:"engine_gap"`
	SatisfiesRequired bool   `json:"satisfies_required"`
}

type CoverageReason struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Class     string `json:"class"`
	EngineGap bool   `json:"engine_gap"`
}

func Build() (Contract, error) {
	checks := dastChecks()
	checks = append(checks, secretsChecks()...)
	checks = append(checks, textscanChecks()...)
	semgrepChecks, err := semgrepChecks()
	if err != nil {
		return Contract{}, err
	}
	checks = append(checks, semgrepChecks...)
	return Contract{
		SchemaVersion: SchemaVersion,
		EngineVersion: StableEngineVersion,
		Checks:        checks,
		Analyzers:     analyzers(),
		Coverage:      coverageContract(),
	}, nil
}

func dastChecks() []Check {
	out := make([]Check, 0, len(scanner.DefaultChecks()))
	for _, check := range scanner.DefaultChecks() {
		auth := "none"
		switch check.Tier() {
		case scanner.TierAuth:
			auth = "single-credential"
		case scanner.TierMultiuser:
			auth = "two-user"
		}
		out = append(out, Check{
			ID: check.Name(), Analyzer: engine.AnalyzerDAST, Category: check.Category(),
			CWEs: []string{}, ExecutionMode: check.Tier().String(), AuthRequirement: auth,
			Applicability: []string{"url"}, Availability: "stable",
		})
	}
	return out
}

func secretsChecks() []Check {
	rules := secrets.CatalogRules()
	out := make([]Check, 0, len(rules))
	for _, rule := range rules {
		out = append(out, Check{
			ID: "secrets/" + rule.ID, FindingID: "SEC-" + rule.ID, Title: rule.Title,
			Analyzer: engine.AnalyzerSecrets, Category: rule.Category, DefaultSeverity: string(rule.Severity),
			Confidence: string(rule.Confidence), CWEs: compactStrings([]string{rule.CWE}), ExecutionMode: "passive",
			AuthRequirement: "none", Applicability: []string{"code"}, Remediation: rule.Remediation, Availability: "stable",
		})
	}
	return out
}

func textscanChecks() []Check {
	rules := textscan.AllRules()
	out := make([]Check, 0, len(rules))
	for _, rule := range rules {
		out = append(out, Check{
			ID: rule.ID, FindingID: "SEC-" + rule.ID, Title: rule.Title,
			Analyzer: engine.AnalyzerTextscan, Category: rule.Category,
			DefaultSeverity: string(rule.Severity), Confidence: string(rule.Confidence),
			CWEs: compactStrings([]string{rule.CWE}), ExecutionMode: "passive", AuthRequirement: "none",
			Applicability: ruleApplicability(rule.Applies), Remediation: rule.Fix, Availability: "stable",
		})
	}
	return out
}

func semgrepChecks() ([]Check, error) {
	rules, err := semgrep.CatalogRules()
	if err != nil {
		return nil, err
	}
	out := make([]Check, 0, len(rules))
	for _, rule := range rules {
		out = append(out, Check{
			ID: rule.ID, Title: firstSentence(rule.Message), Analyzer: engine.AnalyzerSemgrep,
			Category: rule.Category, DefaultSeverity: rule.Severity, Confidence: rule.Confidence,
			CWEs: compactStrings(rule.CWEs), ExecutionMode: "passive", AuthRequirement: "none",
			Applicability: append([]string{}, rule.Languages...), Remediation: strings.TrimSpace(rule.Message),
			Availability: "stable",
		})
	}
	return out, nil
}

func analyzers() []Analyzer {
	base := make(map[string]bool, len(engine.BaseAnalyzers))
	for _, id := range engine.BaseAnalyzers {
		base[id] = true
	}
	out := make([]Analyzer, 0, len(engine.Registry))
	for _, id := range engine.Registry {
		out = append(out, Analyzer{ID: id, BaseStatus: base[id], ProtocolDependent: !base[id], Availability: "stable"})
	}
	return out
}

func coverageContract() CoverageContract {
	classes := make([]CoverageClass, 0, len(reporters.CoverageClasses))
	for _, class := range reporters.CoverageClasses {
		classes = append(classes, CoverageClass{
			ID:                class,
			EngineGap:         class == reporters.ClassUnavailable || class == reporters.ClassFailed,
			SatisfiesRequired: class == reporters.ClassOK || class == reporters.ClassNotApplicable,
		})
	}
	reasons := make([]CoverageReason, 0, len(reporters.ScannerReasons()))
	for _, reason := range reporters.ScannerReasons() {
		state := reporters.ScannerSkipped
		if reason.IsFail() {
			state = reporters.ScannerFailed
		}
		status := reporters.ScannerStatus{State: state, Reason: reason}
		reasons = append(reasons, CoverageReason{ID: string(reason), State: string(state), Class: status.Class(), EngineGap: status.IsGap()})
	}
	return CoverageContract{
		ContractVersion: reporters.CoverageContractVersion,
		RawStates:       []string{string(reporters.ScannerOK), string(reporters.ScannerSkipped), string(reporters.ScannerFailed)},
		Classes:         classes,
		Reasons:         reasons,
	}
}

func ruleApplicability(applies func(string) bool) []string {
	candidates := []struct{ label, path string }{
		{"go", "sample.go"}, {"javascript", "sample.js"}, {"typescript", "sample.ts"},
		{"java", "Sample.java"}, {"dockerfile", "Dockerfile"}, {"yaml", "sample.yaml"},
	}
	var out []string
	for _, candidate := range candidates {
		if applies(candidate.path) {
			out = append(out, candidate.label)
		}
	}
	return out
}

func compactStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func firstSentence(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if index := strings.Index(message, ". "); index >= 0 {
		return message[:index+1]
	}
	return message
}
