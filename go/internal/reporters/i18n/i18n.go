// Package i18n holds the localised strings the HTML reporter renders.
// Sprint 10 (Phase 4.2) added Arabic (`ar`) alongside English (`en`);
// other languages can be added by writing a new constructor that
// returns the same Strings struct.
//
// JSON, SARIF, and PDF outputs deliberately stay English — they're
// machine-consumed and localisation would break downstream tooling.
// HTML is the human-facing surface, so it's the right place to start.
//
// Translation policy: Arabic strings ship as a machine-generated
// baseline marked with `TRANSLATION_REVIEW_NEEDED` in inline comments
// (grep-able). A native-speaker security reviewer is expected to clear
// those comments before Fendix v0.13.0-stable is promoted to public
// release. The risk register entry in
// `tasks/enterprise-readiness/RISKS.md` tracks this.
package i18n

import "strings"

// Strings is the set of user-facing labels the HTML template references.
// Field names mirror the template variables (`{{.I18n.X}}`) verbatim so
// adding a string is a single-step process: add the field here, add a
// translation in every language constructor, reference it in the
// template.
type Strings struct {
	// Document-level
	ReportTitle       string
	ScanSubtitle      string // "{target} — {mode} scan — {duration}"
	GeneratedByFendix string

	// Severities
	SeverityCritical string
	SeverityHigh     string
	SeverityMedium   string
	SeverityLow      string
	SeverityInfo     string

	// Confidence
	ConfidenceHigh   string
	ConfidenceMedium string
	ConfidenceLow    string

	// Section / column headers
	SectionSummary     string
	SectionFindings    string
	SectionRemediation string
	SectionEvidence    string
	SectionReferences  string
	SectionMetadata    string
	ColumnID           string
	ColumnTitle        string
	ColumnSeverity     string
	ColumnLocation     string
	ColumnFix          string

	// UI / labels
	SortByLabel        string
	SortBySeverity     string
	SortByEndpoint     string
	SortBySource       string
	ExpandAll          string
	CollapseAll        string
	FieldEvidence      string
	FieldFix           string
	FieldSource        string
	FieldCategory      string
	FieldConfidence    string
	FieldAffected      string
	FieldReachable     string
	FieldReferences    string
	FieldLocation      string
	ConfidenceLabel    string // appears as "{Source} · {Confidence} confidence"
	StatusBlocking     string // v0.24 decision card
	StatusConfirmed    string // v0.24 decision card
	ScanStartedLabel   string
	DurationLabel      string
	ModeLabel          string
	EndpointsLabel     string
	TotalFindingsLabel string
	NoFindingsMessage  string

	// Coverage (coverage contract v1)
	CoverageTitle                                                                                             string
	CoverageAnalyzer                                                                                          string
	CoverageClass                                                                                             string
	CoverageReason                                                                                            string
	CoverageAttempts                                                                                          string
	CoverageDetail                                                                                            string
	CoverageComplete                                                                                          string
	CoverageIncomplete                                                                                        string // followed by the gap list
	CoverageRequiredMissing                                                                                   string // followed by the required_gaps list
	CoverageNotRecorded                                                                                       string
	CoverageNotMeasured                                                                                       string
	VerdictPass                                                                                               string
	VerdictWarn                                                                                               string
	VerdictBlocked                                                                                            string
	VerdictBlockedCoverageIncomplete                                                                          string
	VerdictCoverageIncomplete                                                                                 string
	ClassOK, ClassNotApplicable, ClassDisabled, ClassUnavailable, ClassUnsupported, ClassFailed, ClassUnknown string
}

// Get returns the strings for the given language code. Unknown codes
// fall back to English (the project's source language). Case-
// insensitive on the input — "AR" and "ar-SA" both resolve to Arabic.
func Get(lang string) Strings {
	switch normalize(lang) {
	case "ar":
		return Arabic()
	default:
		return English()
	}
}

// IsSupported reports whether lang has a translation. Used by the
// CLI flag validator: an unknown code logs a warning AND falls back
// to English, but at startup we still want to tell the user the flag
// value didn't take effect.
func IsSupported(lang string) bool {
	switch normalize(lang) {
	case "en", "ar":
		return true
	default:
		return false
	}
}

// normalize lowercases the input and strips a region suffix
// (`ar-SA` → `ar`). The HTML lang= attribute keeps the full code; the
// dispatch matches on the language portion only.
func normalize(lang string) string {
	low := strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(low, "-_"); i > 0 {
		return low[:i]
	}
	return low
}

// IsRTL reports whether the language is right-to-left. The HTML
// template branches on this to set `dir="rtl"` and apply RTL CSS.
func IsRTL(lang string) bool {
	switch normalize(lang) {
	case "ar", "he", "fa", "ur":
		return true
	default:
		return false
	}
}

// ClassLabel returns the localised label for a lifecycle class string.
func ClassLabel(s Strings, class string) string {
	switch class {
	case "ok":
		return s.ClassOK
	case "not_applicable":
		return s.ClassNotApplicable
	case "disabled":
		return s.ClassDisabled
	case "unavailable":
		return s.ClassUnavailable
	case "unsupported":
		return s.ClassUnsupported
	case "failed":
		return s.ClassFailed
	}
	return s.ClassUnknown
}

// VerdictLabel implements the verdict presentation rule: the release
// decision is primary; incomplete coverage qualifies a BLOCK and is the
// headline only when the decision itself is INCOMPLETE.
func VerdictLabel(s Strings, decision, coverageState string) string {
	var label string
	switch decision {
	case "block":
		if coverageState == "incomplete" {
			return s.VerdictBlockedCoverageIncomplete
		}
		label = s.VerdictBlocked
	case "incomplete":
		return s.VerdictCoverageIncomplete
	case "warn":
		label = s.VerdictWarn
	case "pass":
		label = s.VerdictPass
	default:
		return ""
	}
	if coverageState == "unknown" {
		label += " — " + s.CoverageNotMeasured
	}
	return label
}
