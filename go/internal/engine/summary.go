package engine

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// printCoverageSummary writes the scan-end coverage table (spec §5.8):
// one row per recorded entry, then one line for coverage and, when
// --require-analyzers was given, one for the explicit requirements. It is
// unconditional — strict flags change the exit code, never the report.
func printCoverageSummary(w io.Writer, status scannerStatusList, cov reporters.Coverage, requiredGiven bool) {
	fmt.Fprintln(w, "\nCoverage:")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  analyzer\tclass\treason\tattempts\tdetail")
	for _, s := range status {
		attempts := ""
		if s.Attempts > 1 {
			attempts = fmt.Sprintf("%d", s.Attempts)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", s.Name, s.Class(), s.Reason, attempts, s.Detail)
	}
	tw.Flush()
	if cov.ConfiguredComplete {
		fmt.Fprintln(w, "coverage: complete")
	} else {
		fmt.Fprintf(w, "coverage: incomplete (%s)\n", strings.Join(cov.Gaps, ", "))
	}
	if ap := cov.ActiveProbes; ap != nil {
		// The probes' own account, beside the scan-wide verdict: a complete
		// analyzer is not proof that every probe was evaluated.
		fmt.Fprintln(w, probeSummaryLine(*ap))
	}
	if requiredGiven {
		if len(cov.RequiredGaps) == 0 {
			fmt.Fprintln(w, "required: satisfied")
		} else {
			fmt.Fprintf(w, "required: not delivered (%s)\n", strings.Join(cov.RequiredGaps, ", "))
		}
	}
}

// probeSummaryLine is the one-line account of the active probes printed under
// the coverage verdict. It never begins with "coverage: " or "required: ", the
// prefixes the GitHub Action reads its verdict from.
func probeSummaryLine(ap models.ActiveProbeCoverage) string {
	line := fmt.Sprintf("active probes: %d attempted, %d evaluated, %d not answered by the target, %d gated",
		ap.Attempted, ap.Evaluated, ap.Inconclusive-ap.Gated.Total, ap.Gated.Total)
	if ap.Gated.Total > 0 {
		line += " (" + gatedList(ap) + ")"
	}
	line += fmt.Sprintf(", %d unknown-origin, %d scanner-failed", ap.UnknownOrigin, ap.ScannerFailed)
	if cs := ap.CutShort; cs != nil {
		line += fmt.Sprintf(" (cut short by %s=%s)", cs.Limit, cs.Configured)
	}
	return line
}

// describeGaps renders "name: class (reason)" for each named entry, and
// for a required analyzer disabled by another flag names the contradiction.
func describeGaps(status scannerStatusList, names []string) string {
	byName := map[string]reporters.ScannerStatus{}
	for _, s := range status {
		byName[s.Name] = s
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		s, ok := byName[n]
		if !ok {
			parts = append(parts, n+": not recorded")
			continue
		}
		desc := fmt.Sprintf("%s: %s (%s)", n, s.Class(), s.Reason)
		if s.Class() == reporters.ClassDisabled && s.Detail != "" {
			desc = fmt.Sprintf("required analyzer %s was disabled by %s", n, s.Detail)
		}
		parts = append(parts, desc)
	}
	return strings.Join(parts, "; ")
}
