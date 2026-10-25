package catalog

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/Fendix-app/Fendix/go/internal/engine"
)

// pythonEngineChecksJSON is python/analyzers/check_registry.py's export_json(),
// copied here because the Go module cannot embed files from ../python.
// python/tests/test_check_registry.py fails when the copy is stale, and checks
// the registry itself against the analyzer's emit sites.
//
//go:embed python_engine_checks.json
var pythonEngineChecksJSON []byte

type pythonEngineCheck struct {
	// ID is the bare pattern id (PY_SQL_INJECTION). The catalog does not
	// publish it: checks are named by RuleID.
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	CWE             string   `json:"cwe"`
	Category        string   `json:"category"`
	Languages       []string `json:"languages"`
	DefaultSeverity string   `json:"default_severity"`
	RuleID          string   `json:"rule_id"`
	FindingID       string   `json:"finding_id"`
}

// pythonEngineChecks lists the Python engine's AST (python.ast/PY_*) and
// JavaScript pattern (SEC-JS_*) checks. Like every other analyzer's, each is
// named by the rule_id its findings carry, with the finding's own id as
// finding_id. All of them run in the engine's injection pass, which the scan
// reports as the python-engine/injection analyzer.
func pythonEngineChecks() ([]Check, error) {
	decoder := json.NewDecoder(bytes.NewReader(pythonEngineChecksJSON))
	decoder.DisallowUnknownFields()
	var rows []pythonEngineCheck
	if err := decoder.Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode python_engine_checks.json: %w", err)
	}
	out := make([]Check, 0, len(rows))
	for _, row := range rows {
		out = append(out, Check{
			ID: row.RuleID, FindingID: row.FindingID, Title: row.Title,
			Analyzer: engine.AnalyzerPythonInjection, Category: row.Category,
			DefaultSeverity: row.DefaultSeverity, CWEs: compactStrings([]string{row.CWE}),
			ExecutionMode: "passive", AuthRequirement: "none",
			Applicability: append([]string{}, row.Languages...), Availability: "stable",
		})
	}
	return out, nil
}
