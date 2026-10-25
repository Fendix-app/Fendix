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
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	CWE             string   `json:"cwe"`
	Category        string   `json:"category"`
	Languages       []string `json:"languages"`
	DefaultSeverity string   `json:"default_severity"`
	RuleID          string   `json:"rule_id"`
}

// pythonEngineCatalogIDs renames a Python-engine check whose bare pattern ID
// already names another analyzer's check. The catalog is keyed by ID and the
// docs site routes one page per ID, so two checks cannot share one. textscan
// has its own JS_DOCUMENT_WRITE (category xss, a different pattern).
var pythonEngineCatalogIDs = map[string]string{
	"JS_DOCUMENT_WRITE": engine.AnalyzerPythonEngine + "/JS_DOCUMENT_WRITE",
}

// pythonEngineChecks lists the Python engine's AST (PY_*) and JavaScript
// pattern (JS_*) checks. All of them run in the engine's injection pass,
// which the scan reports as the python-engine/injection analyzer.
func pythonEngineChecks() ([]Check, error) {
	decoder := json.NewDecoder(bytes.NewReader(pythonEngineChecksJSON))
	decoder.DisallowUnknownFields()
	var rows []pythonEngineCheck
	if err := decoder.Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode python_engine_checks.json: %w", err)
	}
	out := make([]Check, 0, len(rows))
	for _, row := range rows {
		id := row.ID
		if renamed, ok := pythonEngineCatalogIDs[id]; ok {
			id = renamed
		}
		out = append(out, Check{
			ID: id, FindingID: row.RuleID, Title: row.Title,
			Analyzer: engine.AnalyzerPythonInjection, Category: row.Category,
			DefaultSeverity: row.DefaultSeverity, CWEs: compactStrings([]string{row.CWE}),
			ExecutionMode: "passive", AuthRequirement: "none",
			Applicability: append([]string{}, row.Languages...), Availability: "stable",
		})
	}
	return out, nil
}
