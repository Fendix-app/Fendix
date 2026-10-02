package models

import (
	"fmt"
	"strings"
)

// ParseFailOn normalises a --fail-on threshold.
//
// Empty means "no threshold": nothing blocks, every MEDIUM+ finding warns.
// A severity name is accepted in any case and with surrounding space, so
// "high", "High" and "HIGH" are the same threshold. Anything else is an error.
//
// It used to be that an unrecognised value only logged a warning, and the
// scan then ran with NO threshold. `--fail-on high` therefore silently
// disabled the gate it asked for: a HIGH finding warned and the run exited 0.
// An unrecognised threshold must refuse the run, never weaken it.
func ParseFailOn(value string) (string, error) {
	normalised := strings.ToUpper(strings.TrimSpace(value))
	switch Severity(normalised) {
	case "":
		return "", nil
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return normalised, nil
	}
	return "", fmt.Errorf("invalid --fail-on %q: use CRITICAL, HIGH, MEDIUM or LOW (any case), or omit it for no threshold", value)
}
