package engine

import (
	"fmt"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// R5-09 (RC-2c, decision D6, gate G2.8): an imported run that its producer says
// failed, or that raised error notifications, has not shown that it evaluated
// anything, so an absent result is not evidence that a finding is gone. Each such
// tool is a coverage gap named "import/<tool>": the coverage is not
// configured_complete, and a gate (`fendix import --fail-on`,
// --fail-on-coverage-gap) exits 2 instead of passing on a run nobody finished.
//
// What counts is only what the producer itself recorded (sarifimport.RunRecord:
// executionSuccessful false, an exit signal, a non-zero exit code with no
// success recorded, error-level notifications of either kind, in any invocation
// of any run of the tool, in any imported file). A run that records nothing, such
// as a SARIF with no invocations, is not a gap: `invocations` is optional in
// SARIF 2.1.0 and an absent key never reads as a failure (OR-11).

// importFailure is why the producer's own account of a tool's runs makes its
// absence of results worthless, or "" when it records no failure.
func importFailure(t reporters.ImportedTool) []string {
	var why []string
	if t.ExecutionSuccessful != nil && !*t.ExecutionSuccessful {
		why = append(why, "the producer reported a failed run; an absent result is not evidence that a finding is gone")
	}
	if t.ErrorNotifications != nil && *t.ErrorNotifications > 0 {
		why = append(why, fmt.Sprintf("the producer reported %d error notification(s); the run may be partial", *t.ErrorNotifications))
	}
	return why
}

// addImportGaps adds one "import/<tool>" gap, with its limitations, for every
// tool whose producer recorded a failed or partial run. Tools keep the order in
// which they first appeared, so the report is deterministic.
func addImportGaps(c *reporters.Coverage, tools []reporters.ImportedTool) {
	for _, t := range tools {
		why := importFailure(t)
		if len(why) == 0 {
			continue
		}
		c.ConfiguredComplete = false
		c.Gaps = append(c.Gaps, "import/"+t.Tool)
		for _, w := range why {
			c.Limitations = append(c.Limitations, "import/"+t.Tool+": "+w)
		}
	}
}

// describeImportGaps names the import gaps in a coverage block, for the message
// of a gate that refused to pass on them. Other gaps are not named here.
func describeImportGaps(tools []reporters.ImportedTool) string {
	var parts []string
	for _, t := range tools {
		if why := importFailure(t); len(why) > 0 {
			parts = append(parts, "import/"+t.Tool+": "+strings.Join(why, "; "))
		}
	}
	return strings.Join(parts, " | ")
}

// describeAllGaps is describeGaps over a coverage block that may also carry
// "import/<tool>" gaps, which no analyzer status describes.
func describeAllGaps(status scannerStatusList, gaps []string, tools []reporters.ImportedTool) string {
	var analyzers []string
	for _, g := range gaps {
		if !strings.HasPrefix(g, "import/") {
			analyzers = append(analyzers, g)
		}
	}
	var parts []string
	if len(analyzers) > 0 {
		parts = append(parts, describeGaps(status, analyzers))
	}
	if imp := describeImportGaps(tools); imp != "" {
		parts = append(parts, imp)
	}
	return strings.Join(parts, "; ")
}
