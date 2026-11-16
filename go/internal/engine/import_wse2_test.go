package engine

import (
	"slices"
	"testing"
)

// Round 6, WS-E2 (R5-09) neighbours of import_round6_test.go.

// A run that raised errors never reads clean because another file of the same
// tool recorded nothing at all: the gap survives the fold across files.
func TestRunImport_WSE2_ErrorsSurviveAFileThatRecordsNothing(t *testing.T) {
	for name, files := range map[string][]string{
		"errors then silent": {"errnotif-success.sarif", "noinvocations.sarif"},
		"silent then errors": {"noinvocations.sarif", "errnotif-success.sarif"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, rep := wse2Import(t, "CRITICAL", files...)
			if c := rep.Metadata.Coverage; c == nil || c.ConfiguredComplete || !wse2ImportGap(rep, "codeql") {
				t.Errorf("coverage %+v: error notifications were dropped by the fold", c)
			}
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
}

// Without a gate the import still exits 0 on a failed run (no --fail-on, no
// --fail-on-coverage-gap asks for one), but the report is incomplete.
func TestRunImport_WSE2_NoGateRequestedExitsZeroButReportsIncomplete(t *testing.T) {
	code, _, rep := wse2Import(t, "", "failed.sarif")
	if code != 0 {
		t.Errorf("exit %d, want 0: nothing asked for a gate", code)
	}
	if c := rep.Metadata.Coverage; c == nil || c.ConfiguredComplete || !wse2ImportGap(rep, "codeql") {
		t.Errorf("the report must still read incomplete with the gap: %+v", c)
	}
}

// A gap names exactly the tools that failed, once each, in first-appearance
// order, however many files and signals contribute.
func TestRunImport_WSE2_GapsAreOncePerToolAndDeterministic(t *testing.T) {
	_, _, rep := wse2Import(t, "CRITICAL", "failed.sarif", "execfalse-only.sarif", "two-producers-semgrep-failed.sarif")
	if got := rep.Metadata.Coverage.Gaps; !slices.Equal(got, []string{"import/codeql", "import/semgrep"}) {
		t.Errorf("gaps = %v, want [import/codeql import/semgrep]", got)
	}
}
