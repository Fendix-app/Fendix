package i18n

import (
	"reflect"
	"testing"
)

// TestStrings_EveryFieldTranslatedInEveryLanguage is the audit test
// en.go's doc comment refers to: every string field in Strings must be
// non-empty in every supported language, so a missing translation shows
// up as a test failure instead of a blank label in a rendered report.
func TestStrings_EveryFieldTranslatedInEveryLanguage(t *testing.T) {
	for _, lang := range []string{"en", "ar"} {
		v := reflect.ValueOf(Get(lang))
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Kind() == reflect.String && v.Field(i).String() == "" {
				t.Errorf("%s: field %s is empty", lang, v.Type().Field(i).Name)
			}
		}
	}
}

func TestVerdictLabel_PresentationRule(t *testing.T) {
	s := Get("en")
	for _, tc := range []struct{ d, c, want string }{
		{"block", "complete", s.VerdictBlocked},
		{"block", "incomplete", s.VerdictBlockedCoverageIncomplete},
		{"incomplete", "incomplete", s.VerdictCoverageIncomplete},
		{"warn", "complete", s.VerdictWarn},
		{"pass", "complete", s.VerdictPass},
		{"pass", "unknown", s.VerdictPass + " — " + s.CoverageNotMeasured},
	} {
		if got := VerdictLabel(s, tc.d, tc.c); got != tc.want {
			t.Errorf("VerdictLabel(%s,%s) = %q, want %q", tc.d, tc.c, got, tc.want)
		}
	}
}
