package models

import (
	"strings"
	"testing"
)

func TestParseFailOnAcceptsEverySeverityInAnyCase(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "CRITICAL", "critical": "CRITICAL", "Critical": "CRITICAL",
		"HIGH": "HIGH", "high": "HIGH", "High": "HIGH", "hIgH": "HIGH", " high ": "HIGH",
		"MEDIUM": "MEDIUM", "medium": "MEDIUM", "Medium": "MEDIUM",
		"LOW": "LOW", "low": "LOW", "Low": "LOW",
	}
	for in, want := range cases {
		got, err := ParseFailOn(in)
		if err != nil || got != want {
			t.Errorf("ParseFailOn(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseFailOnKeepsNoThresholdForEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		got, err := ParseFailOn(in)
		if err != nil || got != "" {
			t.Errorf("ParseFailOn(%q) = %q, %v; want no threshold", in, got, err)
		}
	}
}

func TestParseFailOnRefusesWhatItCannotEnforce(t *testing.T) {
	// INFO is a severity, but not a threshold: nothing classifies as INFO
	// and blocks, so accepting it would silently mean "no threshold".
	for _, in := range []string{"INFO", "info", "severe", "hi", "none", "HIGH,CRITICAL", "3"} {
		got, err := ParseFailOn(in)
		if err == nil {
			t.Errorf("ParseFailOn(%q) = %q, nil; want an error", in, got)
			continue
		}
		if !strings.Contains(err.Error(), "invalid --fail-on") {
			t.Errorf("ParseFailOn(%q) error = %q; want it to name --fail-on", in, err)
		}
	}
}

func TestEveryAcceptedThresholdHasARank(t *testing.T) {
	// The gate compares SeverityRank(threshold); an accepted value with rank 0
	// would be the silent fail-open this parser exists to prevent.
	for _, in := range []string{"critical", "high", "medium", "low"} {
		got, _ := ParseFailOn(in)
		if SeverityRank(Severity(got)) == 0 {
			t.Errorf("accepted threshold %q has rank 0", got)
		}
	}
}
